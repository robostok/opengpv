#! /usr/bin/env python3
  
import os
import sys
import logging
import hashlib
import sqlite3
import _thread
import functools
from datetime import datetime
from utils import myutils
from utils import relay
from utils import greenpasslib
from utils import display
from utils import configsaver

# Configuration:
DEFAULT_CACHE_DIR=functools.reduce(
    os.path.join,
    [ os.path.expanduser("~"), ".local", "greenpass" ]
)

DATABASE_PATH = f"{DEFAULT_CACHE_DIR}/greenpass.db"

display.draw_line1("AVVIO")

# 1. Create Database and Tables
if  os.path.exists(DATABASE_PATH) == False:
    print(f"Creating Database")
    logging.info("Database not found, creating")
    conn_create = sqlite3.connect(DATABASE_PATH)
    conn_create.execute('''CREATE TABLE GP_HASHES
         (GP_HASH TEXT NOT NULL PRIMARY KEY,
         STATUS INT NOT NULL,
         LAST_SEEN TEXT NOT NULL);''')

# At this point the database exists, so connect to database
conn = sqlite3.connect(DATABASE_PATH)

# Used Variables
antiflood_time_gp = 15 #Set in configuration

display.draw_line1("PRONTO",None,display.ICON_QR)
relay.buzzer_ready()

for line in sys.stdin:
    gp_status = -1 #Aladeen
    payload = line.replace('\n', '')

    if payload.find('HC1:') >= 0: #Is a Green Pass
        logging.debug("Found a probable Green pass QR Code")

        hash_object = hashlib.md5(payload.encode())
        gp_hash = hash_object.hexdigest()

        # 2. Check if is in recent hash table
        cursor = conn.execute(f"SELECT GP_HASH, STATUS, LAST_SEEN from GP_HASHES WHERE GP_HASH='{gp_hash}'")
        for row in cursor:
            if (row[1] == 1):
                last_seen_from_now = myutils.datediff(row[2], datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
                if (last_seen_from_now < antiflood_time_gp):
                	gp_status["valid"] = False
                	print("Anti-Flood protection activated")

        # 4. Check validity
        if gp_status==-1:
            # Echo Verifying on display
            gp_status = greenpasslib.verify_greenpass(payload)

        #Call Greenpass library to check validity
        if gp_status["valid"]:
            # 5. Activate Actuator, Bell and whistles
            _thread.start_new_thread(display.draw_line1,("VALIDO","PRONTO",display.ICON_OK,display.ICON_QR))
            _thread.start_new_thread(relay.buzzer_ok,())
            _thread.start_new_thread(relay.close_relay,())

        else :
            _thread.start_new_thread(display.draw_line,("NON VAL","PRONTO",display.ICON_ERR,display.ICON_QR))
            _thread.start_new_thread(relay.buzzer_ko,())

        # 6. Save Transaction into database
        conn.execute(f"REPLACE INTO GP_HASHES (GP_HASH,STATUS,LAST_SEEN) \
      VALUES ('{gp_hash}', {gp_status['valid']}, datetime('now') )");
        conn.commit()

    elif payload.find('CFG:') >= 0:
        logging.debug("Found Configuration QR Code")
        display.draw_line1,("CONFIG",None,display.ICON_CONFIG)

        if(configsaver.write_config(payload)):
        	display.draw_line1,("RIAVVIO",None,display.ICON_CONFIG)
        	_thread.start_new_thread(relay.buzzer_config,())
        	logging.debug("Rebooting System after config update")
        	configsaver.reboot_system()

conn.close()
display.off();
