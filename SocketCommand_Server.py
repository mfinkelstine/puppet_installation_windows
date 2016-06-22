#! -*- coding: utf-8 -*-

import socket, os 
#import wmi
import signal
import re
import logging
import sys, time
import json
from subprocess import Popen, PIPE

from sys import path,exit
from os import getcwd
path.append(os.path.dirname(os.path.realpath(__file__)) + "\\lib")
#print path
import wmicserver

'''
@default variables
'''
debug = 1
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s|%(funcName)-10s|%(levelname)-8s|%(message)s',                
                    datefmt='%m-%d %H:%M',
                    filename='windowsInformation.log',
                    filemode='w')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# set a format which is simpler for console use
formatter = logging.Formatter('%(asctime)-5s|%(funcName)-10s|%(levelname)-8s|%(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

	


def Main():
	host = '9.151.185.38'
	port = 4999
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((host, port))
	
	logging.info("Server [ %s ] start listening to port [ %s ] " %(host,port))
	count = 0
	
	while True:
		s.listen(5)
		clientSocket, addr = s.accept()
		hostData = clientSocket.recv(1024)
		#logging.info("[+] data were recived from [ %s ] count [ %s ]" % (clientSocket , count))
		
		hostInfo = json.loads(hostData)
		logging.info("[+] Data recived from :" )
		logging.info("[|--] [ %s ] " %hostInfo )
		#if not hostInfo:
		#	logging.info("[+] no data were recived from [ %s ] " % hostInfo )
		#	return
		
		hostResults 	= {}
		hostDefenitions = {}
		
			
		while True:
			logging.info("[+] Connecting establish from [ %s ] --- " % str(addr))
			counter = 0

			if hostInfo['check_defnitions']:
				hostDefenitions = hostInfo['check_defnitions']
				
				try:
					wmic = wmicInformation(hostInfo['address'],domain,user,password,addr)
				except:
					logging.error("[|-] Unable to connect with wmic")
					clientSocket.send("wmic_failure")
					clientSocket.close()
					break
				
				if wmic.error == False:
					logging.error( "unable to connect to [ %s ]\n\t\tError Handle : [ %s ] "%(wmic.errorMsg,hostInfo['address'] ))
					break
				
				if debug == 0:
					logging.debug( "defenitions values :\n\t[ %s ] "%hostDefenitions)
				
				for k,v in hostDefenitions.items():
				#logging.info( "items keys [ %s ] values [ %s ]:"%(k,v))
					if k == "osArch":				
						hostResults['osArchitecture']=	wmic.getArch()
					elif k == "osMem" :
						hostResults.update({ k : wmic.getMem() })
					elif k == "osType":
						hostResults['Caption'] = wmic.getCaption()
	
					elif k == "osName":
						hostResults['Name '] = wmic.getHostname()
					elif k == "osPackage":
						print "puppet for windows installation started"
					else: 
						logging.info("no value found for this key : [%s] \t value : [%s]"%(k,v))
				
				logging.info( "Sending Values Back to Client host :")
				logging.info( "RESULTS :  %s  "%hostResults)	
			
				host_information = json.dumps(hostResults).encode('utf-8')
				clientSocket.send(host_information)
				logging.info("[----] Closing Client Connection |%s|",str(clientSocket))
				clientSocket.close()
			
			count = count+1
			break
		#clientSocket.close()
		logging.info("Connection closed with: " + str(addr))

def Exit_gracefully(signal, frame):
	print 'Stop pressing the CTRL+C!'
	sys.exit(0)	

if __name__ == '__main__':
	signal.signal(signal.SIGINT, Exit_gracefully)
	Main()
