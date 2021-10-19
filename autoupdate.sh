#!/bin/bash
cd /home/pi/greenpass
git pull
pip3 install -r requirements.txt
sudo service greenpassverifier restart
