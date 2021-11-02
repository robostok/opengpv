import RPi.GPIO as GPIO
import time

from gpiozero import TonalBuzzer
from gpiozero.tones import Tone


relay_pin = 17
buzzer_pin = 27

GPIO.setmode(GPIO.BCM)
GPIO.setup(relay_pin, GPIO.OUT)

def close_relay():
    try:
        GPIO.output(relay_pin, GPIO.HIGH)
        time.sleep(1)
        GPIO.output(relay_pin, GPIO.LOW)
    
    except KeyboardInterrupt:
    	GPIO.cleanup()

def buzzer_ok():
    b = TonalBuzzer(buzzer_pin)
    for i in range(2):
        b.play(Tone("A5"))
        time.sleep(0.2)
        b.stop()
        time.sleep(0.1) 

def buzzer_ko():
 b = TonalBuzzer(buzzer_pin)
 b.play(Tone("D4"))
 time.sleep(1)
 b.stop()


def buzzer_ready():
   b = TonalBuzzer(buzzer_pin)
   for i in range(3):
       b.play(Tone("A5"))
       time.sleep(0.2)
       b.stop()
       time.sleep(0.1)

def buzzer_config():
    b = TonalBuzzer(buzzer_pin)
    for i in range(2):
        b.play(Tone("A5"))
        time.sleep(1)
        b.stop()
        time.sleep(0.2) 

