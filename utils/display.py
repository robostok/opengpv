from board import SCL, SDA
import busio
import time
from oled_text import OledText,BigLine, SmallLine, Layout32

i2c = busio.I2C(SCL, SDA)

# Create the display, pass its pixel dimensions
oled = OledText(i2c, 128, 32)
oled.disp.rotate(False)
oled.layout = {
	1: BigLine(100, 8, font="FontAwesomeSolid.ttf", size=24),
	2: BigLine(0, 0, font='FreeSans.ttf', size=20),
	3: SmallLine(0, 21, font='FreeSans.ttf', size=12)
}

#oled.layout = Layout32.layout_iconright_1big()

ICON_QR = "\uf029"
ICON_ERR = "\uf00d"
ICON_OK ="\uf164"
ICON_CONFIG = "\uf085"

# Write to the oled
#oled.text(ICON_ERR, 1)  # Line 1
#oled.text("NON VAL", 2)  # Line 2
#oled.text("NO NET", 3)  # Line 2


def draw_line1(strtext,nexttext=None,icon=None,nexticon=None):
	oled.text(strtext, 2)  # Line 1
	if icon !=None:
		oled.text(icon, 1)  # Line 1
	
	if nexttext!=None:
		time.sleep(5)
		oled.text(nexttext, 2)  # Line 1
		if nexticon!=None:
			oled.text(nexticon,1)

def draw_line2(strtext):
	oled.text(strtext,3)

def off():
	oled.clear();
