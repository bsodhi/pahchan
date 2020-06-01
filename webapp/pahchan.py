import argparse
import logging
from datetime import datetime as DT
import views as V
import concurrent
from flask.app import Flask
import json

app = Flask(__name__, static_folder='static', static_url_path='/pahchan/static')
app.register_blueprint(V.vbp, url_prefix='/pahchan')

logging.basicConfig(filename='server.log',
                    level=logging.INFO,
                    format='%(asctime)s %(levelname)s:: %(message)s',
                    datefmt='%d-%m-%Y@%I:%M:%S %p')

TPE = concurrent.futures.ThreadPoolExecutor(max_workers=5)

@app.template_filter('datefmt')
def _jinja2_filter_datefmt(dt, fmt=None):
    if not fmt:
        fmt = V.TS_FORMAT
    dt = DT.strptime(dt, fmt)
    nat_dt = dt.replace(tzinfo=None)
    to_fmt='%d-%m-%Y@%I:%M:%S %p'
    return nat_dt.strftime(to_fmt) 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", type=bool, nargs='?',
                        const=True, default=False,
                        dest="debug", help="Run the server in debug mode.")
    parser.add_argument("cfg_file_path", type=str,
                        help="Scrapper runner config file path.")
    args = parser.parse_args()
    app.secret_key = V.random_str(size=30)
    V._init_db()

    with open(args.cfg_file_path, "r") as cfg_file:
        V.CONFIG = json.load(cfg_file)

    logging.info("CONFIG: "+str(V.CONFIG))
    app.run(host=V.CONFIG["host"],
            port=V.CONFIG["port"],
            threaded=True,
            debug=args.debug)
