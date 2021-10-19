#!/bin/bash

sudo cp systemd/opengpv.service /etc/systemd/system/
systemctl daemon-reload

sudo cp ./autoupdate.sh /etc/cron.daily/autoupdate.sh
sudo chmod +x /etc/cron-.daily/autoupdate.sh
