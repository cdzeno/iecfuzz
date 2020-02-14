#!/usr/bin/python3
from boofuzz import *
import argparse
import binascii
import logging
import socket
import sys

TESTFR = [
        # iec 104 apci layer
        0x68, # start
        0x04, # APDU len
        0x43, # type 0100 0011
        0x00, 0x00, 0x00  # padding        
]

STARTDT = [
        # iec 104 apci layer
        0x68, # start
        0x04, # APDU len
        0x07, # type 0000 0111
        0x00, 0x00, 0x00 # padding 

]

C_IC_NA_1_broadcast = [

        # iec 104 apci layer
        0x68, # start
        0x0e, # apdu len
        0x00, 0x00, # type + tx
        0x00, 0x00, # rx 

        # iec 104 asdu layer
        0x64, # type id: C_IC_NA_1, interrogation command
        0x01, # numix
        0x06, # some stuff
        0x00, # OA 
        0xff, 0xff, # addr 65535
        0x00, # IOA 
        0x00, 0x00, 0x00 # 0x14 

]

IEC_APCI = {
	"680443000000": "TESTFR-ACT",
	"680483000000": "TESTFR-CON",
	"680407000000": "STARTDT-ACT",
	"68040b000000": "STARTDT-CON"
}

def isServiceExposed(host, port):
	logging.info("Searching IEC104 service on %s:%s" % (host, port))
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		try:
			s.settimeout(3.0)
			s.connect((host, int(port)))
			return True
		except socket.error:
			return False

def IECBooFuzz(host, port):
	session = Session(
		target=Target(
			connection=SocketConnection(host, int(port), proto='tcp')
		),
		sleep_time=1,
		receive_data_after_fuzz=True
	)

	# STARTDT:
	# 0x68, -> start
    # 0x04, -> APDU len
    # 0x07, -> type 0000 0111
    # 0x00, 0x00, 0x00 -> padding
	
	s_initialize("iec_startdt")
	if s_block_start("iec_apcii"):
		s_byte(0x68, name="start",fuzzable=False)
		s_byte(0x04, name="apdu_length", fuzzable=False)
		# s_dword(0x07000000, name="type", fuzzable=False)
		s_static("\x07\x00\x00\x00")
	s_block_end("iec_apci")	

	s_initialize("iec_apci_empty")
	if s_block_start("iec_apci"):
		s_byte(0x68, name="start",fuzzable=False)
		s_byte(0x04, name="apdu_length", fuzzable=False)
		# s_dword(0x01000000, name="type", fuzzable=False)
		s_static("\x01\x00\x00\x00")
	s_block_end("iec_apci")	

	s_initialize("iec_clock_sync")
	if s_block_start("iec_apci"):
		s_byte(0x68, name="start",fuzzable=False)
		s_byte(0x14, name="apdu_length", fuzzable=True)
		s_dword(0x000000, name="type", fuzzable=False)
		if s_block_start("iec_asdu"):
			s_byte(0x67, name="type_id",fuzzable=False)   # C_CS_NA_1 Act
			s_byte(0x01, name="sq_plus_no",fuzzable=True) # A-BBBBBBB (1-7 bit)
			s_byte(0x06, name="cot",fuzzable=True)        # T-P/N-COT (1-1-6 bit)
			s_byte(0x00, name="org",fuzzable=False)       # Originator Address
			s_word(0xffff, name="com",fuzzable=True)      # Common Address of ASDU
			if s_block_start("iec_ioa"):                  # Information Object
				s_byte(0x67, name="ioa_1",fuzzable=True)  # IOA: 3-byte length
				s_byte(0x67, name="ioa_2",fuzzable=True)
				s_byte(0x67, name="ioa_3",fuzzable=True)
				s_static("\xee\xd8\x09\x0c\x0c\x02\x14")  # Fixed CP56Time: Feb 12, 2020
			s_block_end("iec_ioa")
		s_block_end("iec_asdu")
	s_block_end("iec_apci")

	s_initialize("iec_inter_command")
	if s_block_start("iec_apci"):
		s_byte(0x68, name="start",fuzzable=False)
		s_byte(0x0e, name="apdu_length", fuzzable=True)
		# s_dword(0x02000000, name="type", fuzzable=False)
		s_static("\x02\x00\x00\x00")
		if s_block_start("iec_asdu"):
			s_byte(0x64, name="type_id",fuzzable=False)   # C_IC_NA_1 Act
			s_byte(0x01, name="sq_plus_no",fuzzable=True) # A-BBBBBBB (1-7 bit)
			s_byte(0x06, name="cot",fuzzable=True)
			s_byte(0x00, name="org",fuzzable=False)
			s_word(0xffff, name="com",fuzzable=True)
			if s_block_start("iec_ioa"):
				s_byte(0x00, name="ioa_1",fuzzable=True)  # IOA: 3-byte length
				s_byte(0x00, name="ioa_2",fuzzable=True)
				s_byte(0x00, name="ioa_3",fuzzable=True)
				s_byte(0x14, name="qoi",fuzzable=True)
			s_block_end("iec_ioa")
		s_block_end("iec_asdu")
	s_block_end("iec_apci")	

	# IEC104 Flow
	# -----------------------------------------------
	# STARTDT act ->
	# STARTDT con <-
	# C_CS_NA_1 Act (Clock syncronization command) ->
	# C_IC_NA_1 Act (Interrogation command) ->
	# M_EI_NA_1 Init (End of initialization) <-
	# M_SP_NA_1 Spont (Single-point information) <-
	# C_CI_NA_1 Act -> 
	# C_IC_NA_1 ActCon <-
	
	session.connect(s_get('iec_startdt'))
	session.connect(s_get('iec_startdt'), s_get("iec_apci_empty"))
	session.connect(s_get("iec_apci_empty"), s_get("iec_clock_sync"))
	session.connect(s_get("iec_apci_empty"), s_get("iec_inter_command"))
	session.connect(s_get("iec_clock_sync"), s_get("iec_inter_command"))
	session.fuzz()

def main():
	parser = argparse.ArgumentParser(description="IEC104 Fuzzer")
	parser.add_argument("--host", action="store", dest="host",
						type=str,required=True,
						help="IEC104 target host to fuzz"
	)
	parser.add_argument("--port", action="store", dest="port",
						type=str,required=True,
						help="IEC104 service port"
	)

	args = parser.parse_args()
	host = args.host
	port = args.port

	if isServiceExposed(host, port):
		logging.info("IEC104 service found active on %s:%s" % (host,port))
		IECBooFuzz(host, port)
	else:
		logging.warn("IEC104 service is not exposed by %s on %s port" % (host,port))
		logging.info("Stopping IEC104 fuzzing on %s:%s" % (host,port))

	logging.info("IEC104 Fuzzing is finished... bye")
	sys.exit(0)
		
if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG,
						format='%(asctime)s - %(message)s',
						datefmt='%d-%b-%y %H:%M:%S')
	main()
