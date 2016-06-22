#! -*- coding: utf-8 -*-

import socket, os 
import wmi
import re
import logging
import sys, time
import json
from subprocess import Popen, PIPE
#from sys import path
#from os import getcwd
#path.append(os.path.dirname(os.path.realpath(__file__)) + "\\lib")

#print path
#print os.path.dirname(os.path.realpath(__file__))

#import wmicserver

#sys.exit(1)

'''
@default variables
'''
debug = 1
connectionSevered=0

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

class Serverlisener:
	def __init__(self,host,port=5000):
		self.port 	= port
		self.host	= host
		
	def server(self):
		"""
		this is the listener class:
		"""
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind((self.host, self.port))
			s.listen(1)
		except socket.error:
			print "unable to create socket"
			
			
		
class wmicInformation(object):
	
	def __init__(self,ip,domain,user,password,connection=None,debug=1):
		self.computer 	= ip
		self.domain 	= domain
		self.username 	= user
		self.password 	= password
		self.connection = connection
		self.debug 		= debug
		if self.debug == 0:
			logging.info("[+] WMIC Connection Information %s"%(10*"#"))
			logging.info("[|-]\tComputer    : %s"%self.computer)
			logging.info("[|-]\tDomain      : %s"%self.domain)
			logging.info("[|-]\tUsername    : %s"%self.username)
			logging.info("[|-]\tPassword    : %s"%self.password)
		self.makeConnection()
	#def getCredentials(self):
		
	def makeConnection(self):	
		if self.debug == 0:
			logging.info( "[+] initialize wmic connaction to [ %s ]" % self.computer)
		if self.domain:
			self.passedUsername = "%s\\%s" %(self.domain, self.username)
		else:
			self.passedUsername = self.username
		
		try:
			if self.debug == 0:
				logging.info( "[|--] wmiConnection :\n\tcomputer=[%s],user=[%s],password=[%s]"%(self.computer,self.passedUsername,self.password))
			self.wmiConnection 	= wmi.WMI( computer=self.computer, user=self.passedUsername, password=self.password )
		except IOError as (errno, strerror):
			print "I/O error({0}): {1}".format(errno, strerror)
		except ValueError:
			print "Could not convert data to an integer."
		except:
			print "Unexpected error:", sys.exc_info()[0]
			raise
		
		#except:
		#	e = sys.exc_info()[0]
		#	self.errorMsg = e
		#	self.error = True
			
	def error(self):
		return self.error
		
	def errorMsg(self):
		return self.errorMsg
		
	def get_uptime(self):
		secs_up = int([uptime.SystemUpTime for uptime in self.wmiConnection.Win32_PerfFormattedData_PerfOS_System()][0])
		hours_up = secs_up / 3600
		return hours_up
		
	def get_cpu(self):
		utilizations = [cpu.LoadPercentage for cpu in self.wmiConnection.Win32_Processor()]
		utilization = int(sum(utilizations) / len(utilizations))  # avg all cores/processors
		return utilization

	def get_mem_mbytes(self):
		available_mbytes = int([mem.AvailableMBytes for mem in self.wmiConnection.Win32_PerfFormattedData_PerfOS_Memory()][0])
		return available_mbytes

	def getMem(self):
		pct_in_use = int([mem.PercentCommittedBytesInUse for mem in self.wmiConnection.Win32_PerfFormattedData_PerfOS_Memory()][0])
		return pct_in_use

	def getArch(self):
		try:
			OSArchitecture = self.wmiConnection.Win32_OperatingSystem(["OSArchitecture"])[0].OSArchitecture
		except Exception, e:
			OSArchitecture = e
		return OSArchitecture
		
	def getHostname(self):
		Name = self.wmiConnection.Win32_ComputerSystem(["Name"])[0].Name
		return Name
		
	def getCaption(self):
		#_in_use = int([mem.Win32_OperatingSystem for mem in self.wmiConnection.Win32_OperatingSystem()][0])
		Caption = self.wmiConnection.Win32_OperatingSystem(["Caption"])[0].Caption
		return Caption
	def ping(self):
		p = Popen('ping -n 1 ' + self.computer, stdout=PIPE)
		m = re.search('Average = (.*)ms', p.stdout.read())
		if m:
			return True
		else:
			raise Exception  

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

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
		if not hostInfo:
			logging.info("[+] no data were recived from [ %s ] " % hostInfo )
			return
		
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
					logging.info("[|-] Unable to connect with wmic")
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
		

if __name__ == '__main__':
	Main()
