#! /bin/bash

# FYI please adress to the following link if 
# you want to install further dependencies in jupyter.pic

apt install python3-pip

pip install virtualenv
python3 -m venv rucio

source rucio/bin/activate

pip install -r PIC-rucio-client/requirements.txt

pip install -Iv rucio-clients==1.23.11

cp Configs/rucio.cfg rucio/etc

export RUCIO_HOME=`pwd`/rucio/

