# load Digilent Waveforms DLL functions
import sys
sys.path.append('/Applications/WaveForms.app/Contents/Resources/SDK/samples/py/')
from ctypes import *
from dwfconstants import *
import math
import time
import serial

from colorama import *
init()

def acquire(serial_input):
#	cdll.LoadLibrary("dwf")  # looks for .dll in C:\Windows\System32
#	dwf = CDLL("dwf")

	if sys.platform.startswith("win"):
    		dwf = cdll.dwf
	elif sys.platform.startswith("darwin"):
    		dwf = cdll.LoadLibrary("/Library/Frameworks/dwf.framework/dwf")
	else:
    		dwf = cdll.LoadLibrary("libdwf.so")

	version = create_string_buffer(16)
	dwf.FDwfGetVersion(version)
#	print("Version: "+str(version.value))

	# interface handle
	hdwf = c_int()
	sts = c_byte()

	# open automatically the first available device
	dwf.FDwfDeviceOpen(-1, byref(hdwf))

	dwf.FDwfDigitalInDividerSet(hdwf, c_int(1))
	dwf.FDwfDigitalInSampleFormatSet(hdwf, c_int(16))

	cSamples = 4096
	rgwSamples = (c_uint16*cSamples)()
	dwf.FDwfDigitalInBufferSizeSet(hdwf, c_int(cSamples))
	
	dwf.FDwfDigitalInTriggerAutoTimeoutSet(hdwf, c_double(0)) #disable auto trigger
	dwf.FDwfDigitalInTriggerSourceSet(hdwf, trigsrcDetectorDigitalIn) #one of the analog in channels
	
	dwf.FDwfDigitalInTriggerPositionSet(hdwf, c_uint(4096))
	
	# dwf.FDwfDigitalInTriggerSet(hdwf, trigtypeEdge)
	# dwf.FDwfDigitalInTriggerChannelSet(hdwf, c_int(0)) # first channel
	# dwf.FDwfAnalogInTriggerLevelSet(hdwf, c_double(1.5)) # 1.5V
	dwf.FDwfAnalogInTriggerConditionSet(hdwf, trigcondRisingPositive)
	# time.sleep(2)
	
	# a = create_string_buffer(16)
	# b = create_string_buffer(16)
	# c = create_string_buffer(16)
	# d = create_string_buffer(16)
	
	dwf.FDwfDigitalInTriggerSet(hdwf, 0, 0, 1, 0)
	time.sleep(1)
	# print dwf.FDwfDigitalInTriggerGet(hdwf, a, b, c, d)
	# print a.value
	# print b.value
	# print c.value
	# print d.value
	
	# begin acquisition
	dwf.FDwfDigitalInConfigure(hdwf, c_bool(0), c_bool(1))
	# print "   waiting to finish"
	
	ser.write(serial_input + '\r\n')

	while True:
		dwf.FDwfDigitalInStatus(hdwf, c_int(1), byref(sts))
		# print "STS VAL: " + str(sts.value)
		if sts.value == stsDone.value :
			break
		# time.sleep(1)
	# print "Acquisition finished"

	# get samples, byte size
	dwf.FDwfDigitalInStatusData(hdwf, rgwSamples, 2*cSamples)

	# out_file = open("test.txt","w")
	samples = [0] * 4096
	
	rgpy=[0.0]*len(rgwSamples)
	for i in range(0,len(rgpy)):
		rgpy[i]=rgwSamples[i]
		# print "%i" % rgpy[i]
		# out_file.write("%d\n" % rgpy[i])
		samples[i] = rgpy[i]
	
	# out_file.close()
	dwf.FDwfDeviceCloseAll()
	
	return samples.count(1)



ser = serial.Serial('/dev/tty.usbmodem101', timeout=1)  # open first serial port
# print ser.name          # check which port was really used
ser.isOpen()


pwd = ['*'] * 6

