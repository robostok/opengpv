#! /usr/bin/env python3
  
import os
import sys
import logging
import hashlib
import sqlite3
import _thread
from datetime import datetime
from utils import myutils
from utils import relay
from utils import greenpasslib
from utils import display
from utils import configsaver

# Configuration:
DATABASE_PATH = "greenpass.db"

display.draw_line1("STARTING")

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
max_time_gp = 3600

display.draw_line1("READY",None,display.ICON_QR)
relay.buzzer_ready()

for line in sys.stdin:
    gp_status = -1 #Aladeen
    payload = line.replace('\n', '')
    print("decoding payload: "+ payload)

    if payload.find('HC1:') >= 0: #Is a Green Pass
        logging.debug("Found a probable Green pass QR Code")

        hash_object = hashlib.md5(payload.encode())
        gp_hash = hash_object.hexdigest()

        print("Hash of Green pass: ", gp_hash)
        # 2. Check if is in recent hash table
        cursor = conn.execute(f"SELECT GP_HASH, STATUS, LAST_SEEN from GP_HASHES WHERE GP_HASH='{gp_hash}'")
        for row in cursor:
            if (row[1] == 1):
                last_seen_from_now = myutils.datediff(row[2], datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
                if (last_seen_from_now > antiflood_time_gp and last_seen_from_now < max_time_gp):
                    print ("Using cached values")
                    gp_status["valid"] = True
                else:
                    if last_seen_from_now < antiflood_time_gp:
                        gp_status["Valid"] = False
                        print("Anti-Flood protection activated")

            print ("GP_HASH = ", row[0])
            print ("STATUS = ", row[1])
            print ("LAST_SEEN = ", row[2])

        # 4. Check validity
        if gp_status<0:
            # Echo Verifying on display
            gp_status = greenpasslib.verify_greenpass(payload)

        #Call Greenpass library to check validity
        if gp_status["valid"]:
            # 5. Activate Actuator, Bell and whistles
            _thread.start_new_thread(display.draw_line1,("VALID","READY",display.ICON_OK,display.ICON_QR))
            _thread.start_new_thread(relay.buzzer_ok,())
            _thread.start_new_thread(relay.close_relay,())

        else :
            _thread.start_new_thread(display.draw_line,("NOT VAL","READY",display.ICON_ERR.display.ICON_QR))
            _thread.start_new_thread(relay.buzzer_ko,())
        # 6. Save Transaction into database
        conn.execute(f"REPLACE INTO GP_HASHES (GP_HASH,STATUS,LAST_SEEN) \
      VALUES ('{gp_hash}', {gp_status['valid']}, datetime('now') )");
        conn.commit()
    elif payload.find('CFG:') >= 0:        
        print("Found Configuration QR Code")
        _thread.start_new_thread(display.draw_line1,("CONFIG","RESTART",display.ICON_CONFIG))
        configsaver.write_config(payload)

conn.close()
display.off();
