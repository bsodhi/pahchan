import concurrent.futures
import glob
import io
import json
import logging
import os
import random
import re
import sqlite3
import string
import sys
import tempfile
import traceback
from datetime import datetime as DT
from functools import wraps
from pathlib import Path

import requests
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)
from flask.helpers import flash, send_file, send_from_directory
from markupsafe import escape
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename
from flask.blueprints import Blueprint

TS_FORMAT = "%Y%m%d_%H%M%S"
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

TPE = concurrent.futures.ThreadPoolExecutor(max_workers=5)

vbp = Blueprint('bp', __name__, template_folder='templates')

def auth_check(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "login_id" not in session:
            logging.warning("Illegal access to operation. Login required.")
            return redirect(url_for('bp.login'))
        return f(*args, **kwargs)
    return wrapper

    
def get_ts_str():
    return DT.now().strftime(TS_FORMAT)


def random_str(size=10):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))


def _init_db():
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        # Create table
        c.execute('''CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
            login_id text NOT NULL UNIQUE, 
            pass_hashed text NOT NULL, full_name text NOT NULL, 
            role text NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS alerts
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
            login_id text NOT NULL, 
            text_to_check text NOT NULL,
            alert_phone text NOT NULL,
            alert_email text NOT NULL,
            disable_alert INTEGER DEFAULT 0,
            UNIQUE(login_id, text_to_check, alert_phone, alert_email)
            )
            ''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts_sent
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
            alert_id INTEGER NOT NULL, 
            sent_on text NOT NULL,
            sent_to text NOT NULL,
            text_found text NOT NULL,
            FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS frames
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
            client_id text NOT NULL,
            frame_file text NOT NULL, 
            received_ts text NOT NULL,
            status text NOT NULL, 
            task_type text NOT NULL,
            detected_text text,
            UNIQUE(frame_file, task_type))
            ''')
        conn.commit()
        logging.info("DB initialized.")


def _authenticate(login_id, plain_pass):
    valid = False
    try:
        with sqlite3.connect('app.db') as conn:
            c = conn.cursor()
            # Create table
            c.execute(
                'SELECT pass_hashed FROM users WHERE login_id=?', (login_id,))
            row = c.fetchone()
            if row:
                valid = pbkdf2_sha256.verify(plain_pass, row[0])
    except Exception as ex:
        logging.exception("Error occurred when authenticating.")
    return valid


def _add_user(login_id, pass_hashed, full_name, role="USER"):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute('SELECT count(*) FROM users WHERE login_id=?', (login_id,))
        if c.fetchone()[0] != 0:
            raise Exception("Login ID already exists.")
        c.execute("""INSERT INTO users(login_id, pass_hashed, full_name, role)
        VALUES (?,?,?,?)""", (login_id, pass_hashed, full_name, role))
        conn.commit()

def _add_alert(login_id, alert_email, alert_phone, text_to_check):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO alerts(login_id, alert_email, 
        alert_phone, text_to_check) VALUES (?,?,?,?)""", 
        (login_id, alert_email, alert_phone, text_to_check))
        conn.commit()


def _get_alerts(login_id=None):
    with sqlite3.connect('app.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if login_id:
            c.execute("SELECT * FROM alerts WHERE login_id=?", (login_id, ))
        else:
            c.execute("SELECT * FROM alerts")
        return c.fetchall()

def _update_alert(id, alert_email, alert_phone, text_to_check, disable_alert):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute("""UPDATE alerts SET alert_email=?, 
        alert_phone=?, text_to_check=?, disable_alert=?
        WHERE id=?""",
        (alert_email, alert_phone, text_to_check, disable_alert, id))
        conn.commit()
        return conn.total_changes


def _add_sent_alert(alert_id, sent_to, text_found):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO alerts_sent(
            alert_id, sent_on, sent_to, text_found)
            VALUES (?,?,?,?)""",
            (alert_id, get_ts_str(), sent_to, text_found))
        conn.commit()

def _get_sent_alerts(alert_id):
    with sqlite3.connect('app.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""SELECT * FROM alerts_sent WHERE alert_id=?
            order by id desc""",
            (alert_id,))
        return c.fetchall()

def _add_frame(client_id, frame_file, task_type):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO frames(client_id, 
        frame_file, received_ts, status, task_type)
        VALUES (?,?,?,?,?)""",
                  (client_id, frame_file, get_ts_str(), "NEW", task_type))
        conn.commit()

def _update_frame(task_type, frame_file, status, detected_text):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute("""UPDATE frames SET status=?, detected_text=?
        WHERE frame_file=? AND UPPER(task_type)=UPPER(?)""",
                  (status, detected_text, frame_file, task_type))
        conn.commit()
        return conn.total_changes


def _get_frames(client_id):
    with sqlite3.connect('app.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""SELECT id, received_ts, status, 
        detected_text, frame_file, task_type 
        FROM frames WHERE client_id=? 
        order by id desc""",
                  (client_id,))
        return c.fetchall()


def _get_frame(id):
    with sqlite3.connect('app.db') as conn:
        c = conn.cursor()
        c.execute("""SELECT id, client_id, frame_file, 
        received_ts, status, detected_text, task_type 
        FROM frames WHERE id=?""", (id,))
        return c.fetchone()


def _fmt_date_str(dt_str):
    try:
        d2 = DT.strptime(dt_str, "%Y%m%d_%H%M%S")
        return d2.strftime("%Y-%b-%d@%H:%M:%S")
    except Exception as ex:
        logging.exception("Failed to format date.")
        return dt_str


# def signup():
#     error = None
#     try:
#         if request.method == 'POST':
#             pw_hashed = pbkdf2_sha256.hash(request.form['password'])
#             _add_user(request.form['login_id'], pw_hashed,
#                       request.form['full_name'])
#             return render_template("index.html",
#                                    error="User created. Please login with your credentials.")

#     except Exception as ex:
#         logging.exception("Error occurred when signing up.")
#         error = str(ex)

#     return render_template('signup.html', error=error)


def login():
    error = None
    try:
        if request.method == 'POST':
            if _authenticate(request.form['login_id'],
                             request.form['password']):
                logging.info("Login successful.")
                session['login_id'] = request.form['login_id']
                return redirect(url_for('bp.home'))
            else:
                error = 'Invalid username/password'
    except Exception as ex:
        logging.exception("Error occurred when logging in.")
        error = str(ex)
    # the code below is executed if the request method
    # was GET or the credentials were invalid
    return render_template('index.html', error=error)


def index():
    return render_template('index.html')


def logout():
    # remove the username from the session if it's there
    session.pop('login_id', None)
    return redirect(url_for('bp.index'))


def invoke_backend_api(file_path, task_type):
    try:
        logging.info("Starting task {0} on file: {1}".format(task_type, file_path))
        data = {"file_path": file_path, "task_type": task_type,
                "callback_url": CONFIG["callback_url"]}
        res = requests.post(CONFIG["backend_url"], json=data)
        res.raise_for_status()
        jr = res.json()
        if jr["status"] != "OK":
            logging.error("API service failed to process request. "+jr["body"])
            _update_frame(task_type, file_path, "ERR", jr["body"])
        else:
            logging.info("API service result: {0}".format(jr["body"]))
            _update_frame(task_type, file_path, "API", jr["body"])
    except Exception as ex:
        logging.exception("Error occurred when invoking backend API.")
        try:
            _update_frame(task_type, file_path, "ERR", str(ex))
        except Exception as e2:
            logging.exception("Failed to update task information in DB.")

def _process_alert(file_path, text):
    try:
        pp = Path(file_path).parts
        alerts = _get_alerts(login_id=pp[-3])
        if not alerts:
            logging.info("No alerts configured by user "+str(pp[-3]))
            return
        for al in alerts:
            email, ttc = al["alert_email"], al["text_to_check"]              
            if re.search(ttc, text):
                logging.info("Sending alert to {0} for match {1}.".format(email, text))
                _add_sent_alert(al["id"], email, text)
                # TODO: Send the email and other forms of alerts
    except Exception as ex:
        logging.exception("Error occurred when processing alerts.")

@auth_check
def base_static(id):
    row = _get_frame(id)
    if row:
        return send_file(row[2])
    else:
        logging.error("No row found for ID {}".format(id))


def api_cb():
    try:
        if request.method != 'POST':
            logging.error("Non-POST request received. Ignoring.")
            return jsonify(status="ERROR", body="Only POST is supported.")
        jr = request.get_json()
        logging.info("Received API callback: "+str(jr))

        file_path = jr["file_path"]
        task_type = jr["task_type"]
        text = jr["text"]
        status = jr["status"]

        if not status or not file_path:
            logging.error("Invalid request: missing required parameters.")
            return jsonify(status="ERROR", body="status and file_path are mandatory.")

        rows = _update_frame(task_type, file_path,
                             "FIN" if status.upper() == "OK" else "ERR",
                             text)
        if rows < 1:
            msg = "No record found for file: '{}'".format(file_path)
            logging.error(msg)
            return jsonify(status="ERROR", body=msg)

        TPE.submit(_process_alert, file_path, text)

        return jsonify(status="OK", body="Record updated successfully.")

    except Exception as ex:
        logging.exception("Error occurred when handling API callback.")
        return jsonify(status="ERROR", body="Error occured: "+str(ex))


@auth_check
def home():
    login_id = session['login_id']
    logging.info("Upload destination: "+UPLOAD_FOLDER)
    try:
        if request.method == 'POST':
            # check if the post request has the file part
            if 'img_file' not in request.files or "task_type" not in request.form:
                msg = "Required arguments not found in request."
                logging.info(msg)
                return render_template('home.html',
                                       error=msg,
                                       name=escape(login_id))
            file = request.files['img_file']
            task_type = request.form['task_type']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                return render_template('home.html',
                                       error="No file data found!",
                                       name=escape(login_id))
            ext = os.path.splitext(file.filename)[1]
            if file and ext in [".jpg", ".png", ".jpeg"]:
                sfn = secure_filename(file.filename)
                task_dir = os.path.join(UPLOAD_FOLDER,
                                        login_id, get_ts_str())
                file_path = os.path.join(task_dir, "input_frame.jpg")
                Path(task_dir).mkdir(parents=True, exist_ok=True)
                file.save(file_path)
                logging.info(
                    "Saved the uploaded file to {0}".format(file_path))
                
                if "hyb" == task_type:
                    _add_frame(login_id, file_path, "ocr")
                    TPE.submit(invoke_backend_api, file_path, "ocr")
                    _add_frame(login_id, file_path, "alpr")
                    TPE.submit(invoke_backend_api, file_path, "alpr")
                else:
                    _add_frame(login_id, file_path, task_type)
                    TPE.submit(invoke_backend_api, file_path, task_type)
                return redirect(url_for('bp.show_status'))
            else:
                logging.error("File type {0} not allowed!".format(ext))
                return render_template('home.html',
                                       error="File type not allowed!",
                                       name=escape(login_id))

        else:
            logging.info("GET request for upload.")

        return render_template('home.html',
                               name=escape(login_id))
    except Exception as ex:
        logging.exception("Error when uploading.")
        return render_template('home.html', error=str(ex),
                               name=escape(login_id))


@auth_check
def show_status():
    login_id = session['login_id']
    try:
        frames = _get_frames(login_id)
        logging.info("Found {0} frames in DB".format(len(frames)))
        return render_template('status.html', data=frames,
                               name=escape(login_id))
    except Exception as ex:
        return render_template('status.html', error=str(ex),
                               name=escape(login_id))

@auth_check
def get_sent_alerts(alert_id):
    try:
        al = _get_sent_alerts(alert_id)
        return render_template('sent_alerts.html', data=al)
    except Exception as ex:
        msg = "Error occurred while fetching sent alerts."
        logging.exception(msg)
        return render_template('sent_alerts.html', error=msg)


@auth_check
def manage_alerts():
    login_id = session['login_id']
    try:
        if request.method == 'POST':
            alert_email = request.form.get("alert_email")
            alert_phone = request.form.get("alert_phone")
            text_to_check = request.form.get("text_to_check")
            disable_alert = request.form.get("disable_alert") != None
            alert_id = request.form.get("alert_id")
            if alert_id:
                _update_alert(alert_id, alert_email, alert_phone, text_to_check, disable_alert)
            else:
                _add_alert(login_id, alert_email, alert_phone, text_to_check)
        
        alerts = _get_alerts(login_id=login_id)
        return render_template('alerts.html', data=alerts)

    except Exception as ex:
        logging.exception("Error when uploading.")
        return render_template('alerts.html', 
        error="Error occurred when processing request.",
                               name=escape(login_id))

CONFIG = None

# Add the view routes
vbp.add_url_rule('/alerts', view_func=manage_alerts, methods=['GET', 'POST'])
# vbp.add_url_rule('/signup', view_func=signup, methods=['GET', 'POST'])
vbp.add_url_rule('/login', view_func=login, methods=['GET', 'POST'])
vbp.add_url_rule('/', view_func=index, methods=['GET'])
vbp.add_url_rule('/logout', view_func=logout, methods=['GET'])
vbp.add_url_rule('/images/<int:id>', view_func=base_static, methods=['GET', 'POST'])
vbp.add_url_rule('/apicb', view_func=api_cb, methods=['POST'])
vbp.add_url_rule('/home', view_func=home, methods=['GET', 'POST'])
vbp.add_url_rule('/status', view_func=show_status, methods=['GET'])
vbp.add_url_rule('/sa/<int:alert_id>', view_func=get_sent_alerts, methods=['GET'])