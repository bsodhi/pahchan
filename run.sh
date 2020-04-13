#!/bin/bash


# ALPR settings
ALPR_HOME=$HOME/alpr-unconstrained
ALPR_PORT=8888
ALPR_URL=http://localhost:$ALPR_PORT/api

# EAST backend settings
EAST_HOME=$HOME/EAST
EAST_PORT=8000
EAST_WORKERS=8
EAST_URL=http://localhost:$EAST_PORT/api
EAST_CHKPT=$EAST_HOME/east_icdar2015_resnet_v1_50_rbox

# Web application settings
WEB_HOME=$HOME/pahchan
WEB_PORT=8796
PEM_DIR=.

set -e # Stop on error

spin_until() {
    while ! grep -i "$1" $2;
    do printf ".";
     sleep 2;
    done
}
echo "Starting ALPR service ..."
source $HOME/.pyenv/PY27/bin/activate
cd $ALPR_HOME
#pip install -r requirements.txt
python api_server.py -p $ALPR_PORT > console.log 2>errors.log &
if [ $? -eq 0 ]
then
    spin_until "Starting" console.log
    echo "ALPR API server started successfully."
else
    echo "Failed to start the ALPR API server."
fi
deactivate

echo "Starting backend EAST service ..."
source $HOME/.pyenv/ML/bin/activate
cd $EAST_HOME/webapp
#pip install -r requirements.txt
python main.py $EAST_PORT $EAST_WORKERS $ALPR_URL $EAST_CHKPT > console.log 2>errors.log &
if [ $? -eq 0 ]
then
    spin_until "Goin" console.log
    echo "Backend API server started successfully."
else
    echo "Failed to start the backend API server."
fi
deactivate

echo "Starting web application ..."
source $HOME/.pyenv/ML/bin/activate
cd $WEB_HOME/webapp
sed -i "s~WEB_PORT~$WEB_PORT~g" run_config.json
sed -i "s~EAST_URL~$EAST_URL~g" run_config.json
sed -i "s~PEM_DIR~$PEM_DIR~g" run_config.json
#pip install -r requirements.txt
python main.py run_config.json > console.log 2>errors.log &
if [ $? -eq 0 ]
then
    spin_until "Debug" console.log
    echo "Web application started successfully."
else
    echo "Failed to start the web application."
fi
deactivate

echo "======= Started all services ======="
