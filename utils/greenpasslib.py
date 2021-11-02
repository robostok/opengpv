# Green Pass Parser
# Copyright (C) 2021  Davide Berardi -- <berardi.dav@gmail.com>
# Modified by Riccardo Bicelli -- <r.bicelli@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import io
import sys
import zlib
import json
import pytz
import cbor2
import base45
import base64
import argparse
import requests
import colorama
import hashlib
import functools
from OpenSSL import crypto
from binascii import hexlify
from datetime import datetime
from cose.keys import EC2Key, CoseKey
from cose.headers import KID
from cose.messages import CoseMessage
import os.path
from os.path import exists
from termcolor import colored

# Colored output
color = False
# Settings output
settings = False
# QR Code file
qrfile = None
# Read text file from stdin
txt = None
# Base url to retrieve data (DGC)
BASE_URL_DGC   = "https://get.dgc.gov.it/v1/dgc/"
# Base url to retrieve data (NHS)
BASE_URL_NHS   = "https://covid-status.service.nhsx.nhs.uk/"
TESTS_URL = "https://covid-19-diagnostics.jrc.ec.europa.eu/devices/export?manufacturer=&text_name=&marking=&rapid_diag=&format=&target_type=&field-1=HSC%20common%20list%20%28RAT%29&value-1=1&search_method=AND"

DEFAULT_CACHE_DIR=functools.reduce(
    os.path.join,
    [ os.path.expanduser("~"), ".local", "greenpass" ]
)

def request_get(url,default=None,headers=None):
    cache_filename=hashlib.md5(url.encode()).hexdigest()
    cache_filename=f"{DEFAULT_CACHE_DIR}/{cache_filename}"
    if exists(cache_filename):
        with open(cache_filename, 'r') as file:
            ret = file.read()
    else:
        if headers==None:
            r = requests.get(url)
        else:
            r = requests.get(url,headers=headers)
        if r.status_code != 200:
            return default
        else:
            ret=r.text
            textfile = open(cache_filename, "w")
            a = textfile.write(ret)
            textfile.close()
    return ret


class TestType(object):
    def __init__(self, t):
        self.t = t
        self._type = {
            "LP6464-4":   "molecular",
            "LP217198-3": "rapid"
        }
        self.pretty_name = self._type

    def get_type(self):
        return self._type.get(self.t, self.t)

    def get_pretty_name(self):
        return self.pretty_name.get(self.t, self.t)

class TestResult(object):
    def __init__(self, t):
        self.t = t

    def is_positive(self):
        return self.t == 260373001

    def is_negative(self):
        return self.t == 260415000

    def is_aladeen(self):
        return not self.is_positive() and not self.is_negative()

    def is_unknown(self):
        return self.is_aladeen()

    def __str__(self):
        if self.is_positive():
            return colored("Positive", "red")
        elif self.is_negative():
            return colored("Negative", "green")
        return colored("Unknown", "yellow")

# Manufacturer names
class Manufacturer(object):
    def __init__(self, t, no_net=False):
        self.t = t
        # Vaccines
        self.pretty_name = {
            "ORG-100001699": "AstraZeneca",
            "ORG-100030215": "Biontech",
            "ORG-100001417": "Janssen",
            "ORG-100031184": "Moderna",
            "ORG-100006270": "Curevac",
            "ORG-100013793": "CanSino",
            "ORG-100020693": "Sinopharm",
            "ORG-100010771": "Sinopharm",
            "ORG-100024420": "Sinopharm",
            "ORG-100032020": "Novavax"
        }
        # Testes
        if not no_net:
            self.pretty_name.update(self.get_tests_pn())

    def get_tests_pn(self):
        o = {}
        r = request_get(TESTS_URL,o)
        if r == o:
            return o
        l = json.loads(r)
        for el in l:
            o[el["id_device"]] = el["commercial_name"]

        return o

    def get_pretty_name(self):
        return self.pretty_name.get(self.t, self.t)

# Vaccine names
class Vaccine(object):
    def __init__(self, t):
        self.t = t
        self.pretty_name = {
            "EU/1/20/1507": "Moderna",
            "EU/1/20/1525": "Janssen",
            "EU/1/20/1528": "Pfizer",
            "EU/1/21/1529": "AstraZeneca",
            "EU/1/XX/XXX1": "Sputnik-V",
            "EU/1/XX/XXX2": "CVnCoV",
            "EU/1/XX/XXX3": "EpiVacCorona",
            "EU/1/XX/XXX4": "BBIBP-CorV",
            "EU/1/XX/XXX5": "CoronaVac",
        }
    def get_pretty_name(self):
        return self.pretty_name.get(self.t, self.t)

# Disease names
class Disease(object):
    def __init__(self, t):
        self.t = t
        self.pretty_name = {
            "840539006": "Covid19"
        }
    def get_pretty_name(self):
        return self.pretty_name.get(self.t, self.t)

# Retrieve settings from unified API endpoint
class SettingsManager(object):
    def __init__(self):
        r = request_get("{}/settings".format(BASE_URL_DGC))
        if r==None:
            print("[-] Error from API")
            sys.exit(1)

        self.vaccines = {}
        self.recovery = {}
        self.test    = {
            "molecular": {},
            "rapid": {}
        }

        settings = json.loads(r)
        # Dispatch and create the dicts
        for el in settings:
            if "vaccine" in el["name"]:
                if self.vaccines.get(el["type"], None) == None:
                    self.vaccines[el["type"]] = {
                        "complete": {
                            "start_day": -1,
                            "end_day": -1
                        },
                        "not_complete": {
                            "start_day": -1,
                            "end_day": -1
                        }
                    }
                if "not_complete" in el["name"]:
                    vtype = "not_complete"
                elif "complete" in el["name"]:
                    vtype = "complete"

                if "start_day" in el["name"]:
                    daytype = "start_day"
                elif "end_day" in el["name"]:
                    daytype = "end_day"

                self.vaccines[el["type"]][vtype][daytype] = int(el["value"])

            elif "recovery" in el["name"]:
                if "start_day" in el["name"]:
                    self.recovery["start_day"] = int(el["value"])
                elif "end_day" in el["name"]:
                    self.recovery["end_day"] = int(el["value"])

            elif "test" in el["name"]:
                if "molecular" in el["name"]:
                    ttype = "molecular"
                elif "rapid" in el["name"]:
                    ttype = "rapid"

                if "start_hours" in el["name"]:
                    hourtype = "start_hours"
                elif "end_hours" in el["name"]:
                    hourtype = "end_hours"

                self.test[ttype][hourtype] = int(el["value"])
            elif "ios" == el["name"] or "android" == el["name"]:
                # Ignore app specific options
                pass
            else:
                print("[~] Unknown field {}".format(el["name"]))

    # Return the time that a test is still valid, negative time if expired
    def get_test_remaining_time(self, test_date, ttype):
        hours = self.test.get(ttype, 0)

        try:
            seconds_since_test = (datetime.now(pytz.utc) - test_date).total_seconds()
            hours_since_test = seconds_since_test / (60 * 60)
        except:
            return 0,0

        valid_start = (hours_since_test - hours["start_hours"])
        valid_end   = (hours["end_hours"] - hours_since_test)

        return valid_start, valid_end

    # Return the time that a vaccine is still valid, negative
    # time if expired
    def get_vaccine_remaining_time(self, vaccination_date, vtype, full):
        if full:
            selector = "complete"
        else:
            selector = "not_complete"

        days = self.vaccines.get(vtype, { "complete": 0, "not_complete": 0})[selector]

        try:
            seconds_since_vaccine = (datetime.now(pytz.utc) - vaccination_date).total_seconds()
            hours_since_vaccine = seconds_since_vaccine / (60 * 60)
        except:
            return 0,0

        valid_start = (hours_since_vaccine - days["start_day"] * 24)
        valid_end   = (days["end_day"] * 24 - hours_since_vaccine)

        return int(valid_start), int(valid_end)

    # Return the time that a recovery certification is still valid, negative
    # time if expired
    def get_recovery_remaining_time(self, recovery_from, recovery_until):
        days = self.recovery

        try:
            seconds_since_recovery = (datetime.now(pytz.utc) - recovery_from).total_seconds()
            hours_since_recovery = seconds_since_recovery / (60 * 60)
        except:
            return 0,0

        valid_start = (hours_since_recovery - days["start_day"] * 24)
        valid_end   = (days["end_day"] * 24 - hours_since_recovery)

        valid_until = (recovery_until - datetime.now(pytz.utc)).total_seconds()
        valid_until = valid_until / (60 * 60)

        valid_end = min(valid_end, valid_until)

        return int(valid_start), int(valid_end)

# Update certificate signer
class CertificateUpdater(object):
    def __init__(self):
        pass

    # Get KEY index from online status page
    def _get_kid_idx(self, kid, _type="dgc"):
        if _type == "dgc":
            r = request_get("{}/signercertificate/status".format(BASE_URL_DGC))
        elif _type == "nhs":
            r = request_get("{}/pubkeys/keys.json".format(BASE_URL_NHS))
        else:
            return ("unk", -1)
        if r==None:
            print("[-] Error from API")
            sys.exit(1)
        i = 0
        hexkid = hexlify(kid)
        for x in json.loads(r):
            if _type == "dgc":
                targetkid = hexlify(base64.b64decode(x))
            if _type == "nhs":
                targetkid = hexlify(base64.b64decode(x["kid"]))
            if targetkid == hexkid:
                return (_type, i)
            i += 1
        return (_type, -1)

    # Dispatch to correct Key IDX retrieve function
    def get_kid_idx(self, kid):
        k = self._get_kid_idx(kid, "dgc")
        if k[1] != -1:
            return k
        k = self._get_kid_idx(kid, "nhs")
        if k[1] != -1:
            return k

        print("[-] Could not find certification authority")
        sys.exit(1)

    # Get key from DGC style repository
    def get_key_dgc(self, idx):
        headers = { "x-resume-token": str(idx) }
        r = request_get("{}/signercertificate/update".format(BASE_URL_DGC), None, headers)
        if r == None:
            print("[-] Error from API")
            sys.exit(1)

        certificate = base64.b64decode(r)

        # Load certificate and dump the pubkey
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
        pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, x509.get_pubkey())[26::]
        return pubkey

    # Get key from NHS style repository
    def get_key_nhs(self, idx):
        r = request_get("{}/pubkeys/keys.json".format(BASE_URL_NHS))
        for x in json.loads(r):
            targetkid = hexlify(base64.b64decode(x["kid"]))
            if targetkid == hexkid:
                return base64.b64decode(x["publicKey"])

    # Retrieve key from remote repository
    def get_key(self, kid):
        keytype, idx = self.get_kid_idx(kid)

        if keytype == "dgc":
            pubkey = self.get_key_dgc(idx)
        elif keytype == "nhs":
            pubkey = self.get_key_nhs(idx)

        # X is the first 32 bits, Y are the remaining ones
        x = pubkey[1:int(len(pubkey)/2) + 1]
        y = pubkey[int(len(pubkey)/2) + 1::]

        # Create COSE key
        kattr = {
                "KTY":   "EC2",
                "CURVE": "P_256",
                "ALG":   "ES256",
                "X":     x,
                "Y":     y
        }
        return CoseKey.from_dict(kattr)

# Parse a green pass file
class GreenPassParser(object):
    def __init__(self, path, filetype="txt"):
        colored=lambda x,y: x
        if filetype == "txt":
            if path == "-":
                line = sys.stdin.read().replace("\n", "")
                outdata = outdata.replace("\n","")                
            else:
                # Modified behavior: if reading from zbarcam input is "continuously" piped so reading
                # through a loop is needed. The workaround is if not passing an existent path to try 
                # decoding the standard input
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        outdata = f.read()
                else:
                    outdata = path.replace("\n","")
                    outdata = bytes(outdata.encode("ASCII"))

        data = b":".join(outdata.split(b":")[1::])
        decoded = base45.b45decode(data)
        uncompressed = zlib.decompress(decoded)

        self.cose = CoseMessage.decode(uncompressed)

        self.kid = self.get_kid_from_cose(self.cose.phdr)
        payload = cbor2.loads(self.cose.payload)

        self.qr_info = {
            "Release Country": payload[1],
            "Release Date":    int(payload[6]),
            "Expiration Date": int(payload[4])
        }

        personal_data = payload[-260][1]
        self.personal_info = {
            "Version":       personal_data["ver"],
            "Date of Birth": personal_data["dob"],
            "First Name":    personal_data["nam"]["gn"],
            "Family Name":   personal_data["nam"]["fn"],
        }

        self.certificate_info = []
        if personal_data.get("v", None) != None:
            # Vaccine
            self.certificate_type = "v"
        elif personal_data.get("t", None) != None:
            # Test
            self.certificate_type = "t"
        elif personal_data.get("r", None) != None:
            # Recovery
            self.certificate_type = "r"
        else:
            print("[-] unrecognized certificate type", file=sys.stderr)
            sys.exit(1)

        for el in personal_data[self.certificate_type]:
            cert = {
                # Common
                "Target disease":              el["tg"],
                "Vaccination or test Country": el["co"],
                "Certificate Issuer":          el["is"],
                "Certificate ID":              el["ci"],
                # Recovery
                "First positive test":         el.get("fr", None),
                "Validity from":               el.get("df", None),
                "Validity until":              el.get("du", None),
                # Common for Test and Vaccine
                "Manufacturer and type":       el.get("ma", None),
                # Test
                "Test type":                   el.get("tt", None),
                "Test name":                   el.get("tn", None),
                "Date of collection":          el.get("sc", None),
                "Test result":                 el.get("tr", None),
                "Testing center":              el.get("tc", None),
                # Vaccine
                "Dose number":                 int(el.get("dn", 0)),
                "Total doses":                 int(el.get("sd", 0)),
                "Vaccine product number":      el.get("mp", None),
                "Vaccine type":                el.get("vp", None),
                "Vaccination Date":            el.get("dt", None),
            }
            self.certificate_info.append(cert)

    # Isolate KID from COSE object
    def get_kid_from_cose(self, phdr):
        for k in phdr.keys():
            if (k == type(KID())):
                return phdr[k]
        print("Could not find KID", file=sys.stderr)
        return None

    # Get Key ID from the QRCode
    def get_kid(self):
        return self.kid

    # Set the decryption key
    def set_key(self, key):
        self.cose.key = key

    # Verify the code
    def verify(self):
        return self.cose.verify_signature()


# Verify certificate
def verify_certificate(path, filetype="txt"):
    gpp = GreenPassParser(path, filetype)
    sm = SettingsManager()

    if gpp.certificate_type == "v":
        certificate_type = "Vaccine"
    elif gpp.certificate_type == "t":
        certificate_type = "Test"
    elif gpp.certificate_type == "r":
        certificate_type = "Recovery"

    for el in gpp.certificate_info:
        dn = -1
        sd = -1

        vaccinedate = None
        recovery_from  = None
        recovery_until = None
        testcollectiondate = None

        expired = True
        vaccine = None
        positive = False
        hours_to_valid = None
        testtype = None
        remaining_hours = None
        for cert_info in tuple(filter(lambda x: x[1] != None, el.items())):
            if cert_info[0] == "Dose number":
                dn = cert_info[1]
            elif cert_info[0] == "Test result":
                t = TestResult(int(cert_info[1]))
                # Strict check, also unknown do not get validated
                positive = not t.is_negative()                
            elif cert_info[0] == "Validity from":
                try:
                    recovery_from = datetime.strptime(cert_info[1], "%Y-%m-%d")
                    recovery_from = pytz.utc.localize(recovery_from, is_dst=None).astimezone(pytz.utc)
                except:
                    recovery_from = 0
            elif cert_info[0] == "Validity until":
                try:
                    recovery_until = datetime.strptime(cert_info[1], "%Y-%m-%d")
                    recovery_until = pytz.utc.localize(recovery_until, is_dst=None).astimezone(pytz.utc)
                except:
                    recovery_until = 0
                certdate = recovery_from
            elif cert_info[0] == "Total doses":
                sd = cert_info[1]
            elif cert_info[0] == "Vaccine product number":
                vaccine = cert_info[1]                
            elif cert_info[0] == "Test type":
                testtype = cert_info[1]                                
            elif cert_info[0] == "Vaccination Date":
                try:
                    vaccinedate = datetime.strptime(cert_info[1], "%Y-%m-%d")
                    vaccinedate = pytz.utc.localize(vaccinedate, is_dst=None).astimezone(pytz.utc)
                except:
                    vaccinedate = 0
                certdate  = vaccinedate
            elif cert_info[0] == "Date of collection":
                try:
                    testcollectiondate = datetime.strptime(cert_info[1], "%Y-%m-%dT%H:%M:%S%z")
                except:
                    testcollectiondate = 0
                certdate = testcollectiondate
        
        # Check test validity
        if testcollectiondate != None and testtype != None:
            color = "white"
            ttype = TestType(testtype)
            hours_to_valid, remaining_hours = sm.get_test_remaining_time(testcollectiondate, ttype.get_type())

        # Check vaccine validity
        if vaccinedate != None and vaccine != None:
            color = "white"
            hours_to_valid, remaining_hours = sm.get_vaccine_remaining_time(vaccinedate, vaccine, dn == sd)

        # Check recovery validity
        if recovery_from != None and recovery_until != None:
            color = "white"
            hours_to_valid, remaining_hours = sm.get_recovery_remaining_time(recovery_from, recovery_until)

        if hours_to_valid != None and remaining_hours != None:
            if hours_to_valid < 0:
                color = "red"
                remaining_hours = "Not yet valid, {:.0f} hours to validity, {} days".format(
                        hours_to_valid, int(hours_to_valid / 24)
                )
                remaining_days = remaining_hours
                expired = True
            elif remaining_hours <= 0:
                color = "red"
                remaining_days = "Expired since {:.0f} hours, {} days".format(
                        -remaining_hours,
                        -int(remaining_hours / 24)
                )
                expired = True
            elif remaining_hours * 24 < 14:
                color = "yellow"
                remaining_hours = "{:.0f} hours left ({} days)".format(remaining_hours, int(remaining_hours / 24))
                remaining_days = remaining_hours
                expired = False
            else:
                color = "green"
                remaining_days = "{:.0f} hours left, {} days, ~ {} months".format(
                    remaining_hours,
                    int(remaining_hours / 24),
                    round(remaining_hours / 24 / 30)
                )
                expired = False


    cup = CertificateUpdater()
    key = cup.get_key(gpp.get_kid())
    gpp.set_key(key)
    verified = gpp.verify()

    unknown_cert = gpp.certificate_type not in ( "v", "t", "r" )

    valid = verified and not expired and not positive and not unknown_cert

    rt = {
        "first_name" : gpp.personal_info["First Name"],
        "last_name" : gpp.personal_info["Family Name"],
        "birth_date": gpp.personal_info["Date of Birth"],
        "valid": valid }

    return rt
    

def dump_settings():
    sm = SettingsManager()

    print("Tests")
    for el in sm.test.items():
        print("  {} not before: {:4d} hours   not after: {:4d} hours".format(
            colored("{:25s}".format(el[0]), "blue"), el[1]["start_hours"], el[1]["end_hours"])
        )
    print()
    print("Certifications")
    print("  {} not before: {:4d} days    not after: {:4d} days".format(
        colored("{:25s}".format("recovery"), "blue"), sm.recovery["start_day"], sm.recovery["end_day"])
    )
    print()

    print("Vaccines")
    for vac in sm.vaccines.items():
        for el in vac[1].items():
            print("  {} {} not before: {:4d} days    not after: {:4d} days".format(
                colored("{:12s}".format(el[0]), "blue"),
                colored("{:12s}".format(Vaccine(vac[0]).get_pretty_name()), "yellow"),
                el[1]["start_day"], el[1]["end_day"]
                )
            )
    print()

def verify_greenpass(payload):
   res = verify_certificate(payload,"txt")
   return res
