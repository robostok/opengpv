import configparser
import base64
import hashlib
import tempfile
import os

def decode_config(config_str):
	try:
		config_str=config_str.replace("CFG:","")
	
		config_str=base64.b64decode(config_str)
		config_str=str(config_str,"utf-8")
		return config_str
	except:
		return ""
		
# Write coniguration from QR Code
def write_config(config_str):
	try:
		config_str=decode_config(config_str)
		
		config = configparser.ConfigParser()
		config.read_string(config_str)	
		
		# Write wpa_supplicant.conf
		if ( "wireless" in config.sections() ):
			wireless_conf = f"""country={config.get("wireless","country")}
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={{
	ssid="{config.get("wireless","ssid")}"
	scan_ssid=1
	psk="{config.get("wireless","psk")}"
	key_mgmt=WPA-PSK
}}"""
			#Write Temporary File
			f = tempfile.NamedTemporaryFile(delete=False)
			f.write(wireless_conf.encode())
			f.close()
			#Copy to boot	
			os.system(f"sudo cp -f {f.name} /boot/wpa_supplicant.conf")
			os.unlink(f.name)		
		return True
	except Exception as e:
		print(e)
		return False
	
	
def validate_config(config):
	print("validation")

def check_pin(pin_hash):
	print("Ciao")
	
def reboot_system():
	os.system("sudo reboot")
