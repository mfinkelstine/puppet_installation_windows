#! -*- coding: utf-8 -*-

import socket, os 
import wmi
import re
import logging
import sys, time
import json
from _winreg import (HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, OpenKey, EnumValue, QueryValueEx)
import subprocess 
import win32com.client

from sys import path
# python c:\python_scripts\puppet_installation_windows\SocketCommandServerA.py
from os import getcwd
path.append(os.path.dirname(os.path.realpath(__file__)) + "\\lib")

#print path
#print os.path.dirname(os.path.realpath(__file__))

#import wmicserver

#sys.exit(1)

'''
@default variables
'''
domain 		= "ENG"
user 		= "meirfi"
password 	= "1q2w3e4r5t"

debug = 1
connectionSevered=0

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s|%(funcName)-25s|%(levelname)-8s|%(message)s',                
                    datefmt='%m-%d %H:%M',
                    filename='server_listner.log',
                    filemode='w')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# set a format which is simpler for console use
#formatter = logging.Formatter('%(asctime)-5s|%(funcName)-16s|%(levelname)-8s|%(message)s')
formatter = logging.Formatter('%(asctime)-5s|%(levelname)-8s|%(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

class wmicInformation(object):
	
	def __init__(self,ip,domain,user,password,connection=None,debug=False):
		self.computer 		= ip
		self.domain 		= domain
		self.username 		= user
		self.password 		= password
		self.connection 	= connection
		self.debug 			= debug
		self.globPassword 	= "abcd_1234"
		self.psexec			= 'C:\\PsTools\\psexec.exe '
		self.Version 		= None
		if self.debug:
			logging.debug("[|-] WMIC Connection Information %s"%(10*"#"))
			logging.debug("[|-]\tComputer    : %s"%self.computer)
			logging.debug("[|-]\tDomain      : %s"%self.domain)
			logging.debug("[|-]\tUsername    : %s"%self.username)
			logging.debug("[|-]\tPassword    : %s"%self.password)
		self.makeConnection()
	#def getCredentials(self):
		
	def makeConnection(self):	
		if self.debug:
			logging.debug( "[|-] initialize wmic connaction to [ %s ]" % self.computer)
		if self.domain:
			self.passedUsername = "%s\\%s" %(self.domain, self.username)
		else:
			self.passedUsername = self.username
		
		try:
			#if self.debug:
			#	logging.debug( "[|-] wmiConnection :\n\tcomputer=[%s],user=[%s],password=[%s]"%(self.computer,self.passedUsername,self.password))
			if self.computer == "9.151.185.38":
				self.wmiConnection 	= wmi.WMI( computer="." )
			else:
				self.wmiConnection 	= wmi.WMI( computer=self.computer, user=self.passedUsername, password=self.password )
		except IOError as (errno, strerror):
			print "[|-] I/O error({0}): {1}".format(errno, strerror)
		except ValueError:
			print "[|-] Could not convert data to an integer."
		except:
			matchObj = re.match("wmi.x_access_denied", sys.exc_info()[0])
			if matchObj:
				self.wmiConnection = matchObj
				print "[|-] Unexpected error:", matchObj
			else:
				self.wmiConnection = sys.exc_info()[0]
				print "[|-] Unexpected error:", sys.exc_info()[0]
			raise
			
	def error(self):
		return self.error
		
	def errorMsg(self):
		return self.errorMsg
		
	def get_uptime(self):
		secs_up = int([uptime.SystemUpTime for uptime in self.wmiConnection.Win32_PerfFormattedData_PerfOS_System()][0])
		hours_up = secs_up / 3600
		if self.debug:
			logging.debug( "[|-] get_uptime [ %s ] [ %s ]" %(self.computer, hours_up))
		return hours_up
		
	def get_cpu(self):
		utilizations = [cpu.LoadPercentage for cpu in self.wmiConnection.Win32_Processor()]
		utilization = int(sum(utilizations) / len(utilizations))  # avg all cores/processors
		if self.debug:
			logging.debug( "[|-] get_cpu [ %s ] [ %s ]" %(self.computer, utilization))
		return utilization

	def get_mem_mbytes(self):
		available_mbytes = int([mem.AvailableMBytes for mem in self.wmiConnection.Win32_PerfFormattedData_PerfOS_Memory()][0])
		if self.debug:
			logging.debug( "[|-] get_mem_mbytes [ %s ] [ %s ]" %(self.computer, available_mbytes))
		return available_mbytes

	def getMem(self):
	 # "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
		pct_in_use = int([mem.PercentCommittedBytesInUse for mem in self.wmiConnection.Win32_PerfFormattedData_PerfOS_Memory()][0])
		if self.debug:
			logging.debug( "[|-] getMem [ %s ] [ %s ]" %(self.computer, pct_in_use))
		return pct_in_use

	def getArch(self):
		try:
			OSArchitecture = self.wmiConnection.Win32_OperatingSystem(["OSArchitecture"])[0].OSArchitecture	
		except:
			if re.search("x_wmi_invalid_query", str(sys.exc_info()[0])):
				try:
					OSArchitecture = self.wmiConnection.Win32_Processor(["Addresswidth"])[0].Addresswidth
				except:
					if re.search("x_wmi_invalid_query", str(sys.exc_info()[0])):
						print "[|-] wmi invalid query: [ %s ]"%sys.exc_info()[0]
						OSArchitecture = "x_wmi_invalid_query"
			else:
				print "[|-] Unexpected error:", sys.exc_info()[0]
				return "Unexpected error:", sys.exc_info()[0]
		if self.debug:
			logging.debug( "[|-] getArch [ %s ] [ %s ]" %(self.computer, OSArchitecture))		
		return OSArchitecture
		
	def getHostname(self):
		Name = self.wmiConnection.Win32_ComputerSystem(["Name"])[0].Name
		self.hostname = Name
		if self.debug:
			logging.debug( "[|-] getHostname [ %s ] [ %s ]" %(self.computer, Name))	
		return Name
		
	def getCaption(self):
		#_in_use = int([mem.Win32_OperatingSystem for mem in self.wmiConnection.Win32_OperatingSystem()][0])
		Caption = self.wmiConnection.Win32_OperatingSystem(["Caption"])[0].Caption
		if self.debug:
			logging.debug( "[|-] getCaption [ %s ] [ %s ]" %(self.computer, Caption)) 
		return Caption
	def getSoftwareVrsion(self):
		if not self.Version:
			
			if self.debug:
				logging.debug( "[|-] getSoftwareVrsion [ %s ] [ %s ]" %(self.computer, self.Version)) 
			return "undefined.version"
			
		else:
			if re.search("2003", self.getCaption()):
				return "unknow.version"
			else:
				return self.Version
			
			
	def getBuildNumber(self):
		BuildNumber = self.wmiConnection.Win32_OperatingSystem(["BuildNumber"])[0].BuildNumber
		if self.debug:
			logging.debug( "[|-] getBuildNumber [ %s ] [ %s ]" %(self.computer, BuildNumber)) 
			
		return BuildNumber
		
	def ping(self):
		p = Popen('ping -n 1 ' + self.computer, stdout=PIPE)
		m = re.search('Average = (.*)ms', p.stdout.read())
		if m:
			if self.debug:
				logging.debug( "[|-] ping [ %s ] [ %s ]" %(self.computer, "True")) 
			return True
		else:
			raise Exception  
	
	def getInstalledSoftware(self,application,install=None):
		if self.getWinInstalledSoftware():
			logging.info( "[|-] software [ %s ] already installed  " %application)
			installation_results="already_installed"
		else:
			os_arch = str(self.getArch())
			logging.info( "[|-] Running Installation software [ %s ] procedure on host [ %s ] os_arch [ %s ]" %(application,install , os_arch ))
			if re.search("64", os_arch):
				logging.info("[|-] installing [%s] for system architecture [ %s ]"%( application, os_arch))
				installation_results = self.getSoftwareInstallation("64",application)
			else:
				logging.info("[|-] installing [%s] for system architecture [ %s ]"%( application, os_arch))
				installation_results = self.getSoftwareInstallation("32",application)
		
		if self.debug:
				logging.debug( "[|-] getInstalledSoftware [ %s ] [ %s ]" %(self.computer, installation_results)) 		
		return installation_results
		
	def getSoftwareInstallation (self,os_arch,app_name):
		
		puppet_PACAKGE_TYPE = ""
		host_name 				= self.getHostname()
		logfile 				= 'logfile_'+host_name.lower()+'.txt'
		log_path				= 'c:\\'
		puppet_installation_log	= log_path+''+logfile
		
		if os_arch == "64":
			puppet_PACAKGE_TYPE 	= 'puppet-3.7.1-x64.msi'			
		elif os_arch == "32":
			puppet_PACAKGE_TYPE 	= 'puppet-3.7.1.msi'
		else:
			print "unknown OS Architecture for pacakge installation [ %s ]"%os_arch
		
		remote_path='\\\\9.151.185.38\\puppet-windows\\data'
		puppet_installation_msi		=	remote_path+'\\'+puppet_PACAKGE_TYPE
		puppet_INSTALLDIR			=	'INSTALLDIR=C:\\puppet'
		puppet_MASTER_SERVER		=	'PUPPET_MASTER_SERVER=puppet.xiv.ibm.com'
		
		hostadmin = host_name+'\Administrator'
		passwd 	  = 'abcd_1234'
	
		#ps_exec='C:\PsTools\psexec.exe -s \\\\'+self.computer+' -u '+hostadmin+' -p '+passwd
		ps_exec='C:\PsTools\psexec.exe '
		remoteHostConfiguration = '\\\\'+self.computer+' -u '+hostadmin+' -p '+self.globPassword
		executible_msi = 'msiexec.exe /qn /norestart /l*vx '+puppet_installation_log+' /i '+puppet_installation_msi+' '+puppet_INSTALLDIR+' '+puppet_MASTER_SERVER
		installPackage = ps_exec+" "+remoteHostConfiguration+' '+executible_msi
		
		if self.debug: 
			logging.debug( "[|-] psexec command :\n\t"+ps_exec)
			logging.debug( "[|-] msi installation command :\n\t"+executible_msi)
			logging.debug( "[|-] sending installation to "+host_name)
			logging.debug( "[|-] command "+installPackage)
			return "debug mode"
		else: 
			logging.info("[|-] Starting installation procedure")
			exit_status = self._cmd(installPackage)
			if exit_status == 0:
				self.copyCoinfigurationFiles()
				self._serviceRestart()
				return "success"
			else:
				return "failed"
		
	
	def copyCoinfigurationFiles(self):
		puppet_CONF_FILE			= 	"puppet.conf"
		puppet_PATH_COPY			= 	[ 'C:\\ProgramData\\PuppetLabs\\puppet\\etc\\' , 'C:\\ProgramData\\Application Data\\PuppetLabs\\puppet\\etc\\' ]
		puppet_CONFIGURATION_FILES 	= 	[ "owner", "itcsgroup" ]
		remote_path='\\\\9.151.185.38\\puppet-windows\\data'
		hostadmin = self.getHostname()+'\Administrator'
		remoteHostConfiguration = '\\\\'+self.computer+' -u '+hostadmin+' -p '+self.globPassword
		
		logging.info("[|-] copying configuration files installation procedure")
		for path in range(len(puppet_PATH_COPY)):
			copyConfiguration = self.psexec+' -i -d '+remoteHostConfiguration+' cmd /c copy "'+remote_path+'\\'+puppet_CONF_FILE+'" "'+puppet_PATH_COPY[path]+'"'
			if self.debug: logging.debug("[|-] installation package : [ %s ]" %copyConfiguration)
			else: self._cmd(copyConfiguration)
		
		logging.info("[|-] creating installation date file")
		installdate = self.psexec+' -i -d '+remoteHostConfiguration+' cmd ""/c date /T > C:\\puppet\\installdate" '
		if self.debug:
				logging.debug("[|-] installation date : [ %s ]" %installdate)
		else: self._cmd(installdate)
			#psexec -i -d \\9.151.184.47 -u "SVTMAIL\Administrator" -p "abcd_1234" cmd.exe " /c date /T > C:\puppet\installdate "
		
		for file in range(len(puppet_CONFIGURATION_FILES)):
			copyConfiguration = self.psexec+' -i -d '+remoteHostConfiguration+' cmd /c copy "'+remote_path+'\\'+puppet_CONFIGURATION_FILES[file]+'" C:\\Windows\\"'+puppet_CONFIGURATION_FILES[file]+'"'
			if self.debug:
				logging.debug("[|-] installation package : [ %s ]" %copyConfiguration)
			else: self._cmd(copyConfiguration)
	
	def getSoftwareType(self,app_name):
		os_arch = str(self.getArch())
		#print "os_arch is %s " %os_arch
		if re.search("64", os_arch ):
			appType = str(app_name)+"_x64"
		else:
			appType = str(app_name)+"_x86"
		
		if self.debug:
				logging.debug( "[|-] getSoftwareType [ %s ] [ %s ]" %(self.computer, appType)) 
		
		return appType
	
	def _cmd(self,command):
		p = subprocess.Popen( command , stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell = True ) 
		return_code = p.wait()
		if self.debug:
				logging.debug( "[|-] _cmd [ %s ] [ %s ]" %(self.computer, return_code)) 
		return return_code
		
	def _serviceRestart(self):
		hostadmin = self.getHostname()+'\Administrator'
		remoteHostConfiguration = '\\\\'+self.computer+' -u '+hostadmin+' -p '+self.globPassword
		
		logging.info("[|-] Stop/Start services...")
		serviceStop = self.psexec+' -i -d '+remoteHostConfiguration+' net stop "Puppet Agent"'
		if self.debug: logging.debug("[|-] installation package : [ %s ]" %serviceStop)
		else: 
			status = self._cmd(serviceStop)
			if status == False:
				logging.debug("[|-] failed to stop service : [ %s ]" %serviceStop)
				return 
				
		serviceStart = self.psexec+' -i -d '+remoteHostConfiguration+' net start "Puppet Agent"'
		if self.debug: logging.debug("[|-] installation package : [ %s ]" %serviceStart)
		else: 
			status = self._cmd(serviceStart)
			if status == False:
				logging.debug("[|-] failed to start service : [ %s ]" %serviceStart)
		
	def _checkProcess(self,p):
		for i in c.Win32_Process(["Caption", "ProcessID"]):
			print i
	def getServiceStatus(self):
		logging.info("[|-] %s Service list [ %s ]"%(5*"#",20*"-"))
		service_status=False
		for s in self.wmiConnection.Win32_Service():
			if re.search("Puppet Agent", s.Caption):
				if self.debug: logging.debug("[|-] Service name [ %s ] service State [ %s ]"%(s.Caption , s.State))
				service_status=True
		return service_status
		
	def getWinInstalledSoftware(self):
		#import win32com.client
		installed=False
		if re.search("2003", self.getCaption()):
			print "Windows 2003"
		else:
			
			hostServiceList	=	{}
			objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
			objSWbemServices = objWMIService.ConnectServer(self.computer,"root\CIMV2")
			colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_Product")
		
			for objItem in colItems:
				if not objItem.Caption:
					self.Caption = "undefined.Caption"
					self.Version = None
				else:
					if re.search("Puppet", objItem.Caption):
						installed=True
						self.Caption = objItem.Caption
						self.Version = objItem.Version
				#print "Caption: ", objItem.Caption
		
		logging.info("[|-] software installation status %s" %installed)
		
		return installed
	
def is_json(myjson,debug=False):
	try:
		json_obj = json.loads(myjson)
		if debug: logging.info("[|-] JSON Data recevied  [ %s ]"%json_obj )
		#return json_obj
	except ValueError, e:
		return False
	except Exception, e:
		logging.error('Failed to upload to ftp: '+ str(e))
		return False
	return True
	
def Main():
	host = '9.151.185.38'
	port = 4999
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((host, port))
	#s = Serverlisener(host)
	
	logging.info("Server [ %s ] start listening to port [ %s ] " %(host,port))
	count = 0
	
	while True:
		s.listen(5)
		clientSocket, addr = s.accept()
		hostData = clientSocket.recv(1024)
		#logging.info("[+] data were recevied from [ %s ] count [ %s ]" % (clientSocket , count))
		
		#hostInfo = json.loads(hostData)
		#hostInfo = is_json(hostData)
		#if hostInfo == False:
		
		if is_json(hostData):
			hostInfo = json.loads(hostData)
			if hostInfo['info']['debug']:
				logging.debug("[+] no data were recevied from [ %s ] " % hostInfo )
			
		else:
			if hostInfo['info']['debug']: logging.info("[+] no data were recevied from [ %s ] " % hostInfo )
			logging.error("[+] no data were recevied from %s " % addr[0])
			clientSocket.send("error_data")
			clientSocket.close()
			return
		
		hostResults 	= {}
		#hostDefenitions = {}
		pacakge_info	= {}
		while True:
			logging.info("[+] Connecting establish from [ %s ] for host [ %s ]" % (addr[0],hostInfo['info']["address"]))

				
			if hostInfo['check_defnitions']:
				if hostInfo['info']['debug']:
					logging.debug("[|-] Host/User Information [ %s ] " % hostInfo['info'])
					logging.debug("[|-] Host/User Defnitions  [ %s ] " % hostInfo['check_defnitions'])
					logging.debug("[|-] Package software defenitions [ %s ] " % hostInfo['package_info'])
				try:
					wmic = wmicInformation(hostInfo['info']['address'],hostInfo['info']['domain'],hostInfo['info']['username'],hostInfo['info']['password'],addr,hostInfo['info']['debug'])
				except:
					logging.info("[|-] Unable to connect with wmic")
					clientSocket.send("wmic_failure")
					clientSocket.close()
					break
					
				if wmic == "wmi.x_access_denied":
					clientSocket.send(wmic)
					clientSocket.close()
					break
					

				if hostInfo['info']['debug']:
					logging.info("[|-] debug mode have been enabled all recoreds will be directed to log file")
				
				for k,v in hostInfo['check_defnitions'].items():				
					if hostInfo['info']['debug']: logging.debug( "items keys [ %s ] values [ %s ]:"%(k,v) )
					
					if k == "osArch":
						if hostInfo['info']['debug']: 
							#logging.debug( "[%s] : [ %s ] "%(k,'debug mode'))
							#hostResults.update({"osArchitecture" : 'osArchitecture' })
							hostResults.update({"osArchitecture" : str(wmic.getArch()) })
						else: hostResults.update({"osArchitecture" : str(wmic.getArch()) })
					elif k == "osMem" :
						
						if hostInfo['info']['debug']: 
							#logging.debug( "[%s] : [ %s ] "%(k,'debug mode'))
							#hostResults.update({ k : k })
							hostResults.update({ k : int(wmic.getMem()) })
						else: hostResults.update({ k : int(wmic.getMem()) })
					elif k == "osType":

						if hostInfo['info']['debug']: 
							#logging.debug( "[%s] : [ %s ] "%(k,'debug mode'))
							hostResults.update({"Caption" : wmic.getCaption()})
							hostResults.update({"BuildNumber" : wmic.getBuildNumber()})
						else:
							hostResults.update({"Caption" : wmic.getCaption()})
							hostResults.update({"BuildNumber" : wmic.getBuildNumber()})
							
					elif k == "osName":

						if hostInfo['info']['debug']: 
							#logging.debug( "[%s] : [ %s ] "%(k,'debug mode'))
							#hostResults.update({"Name": 'Name' })
							hostResults.update({"Name":wmic.getHostname()})
						else:
							hostResults.update({"Name":wmic.getHostname()})
							
					elif k == "osPackage" and hostInfo['check_defnitions'][k] == True :
						if hostInfo['info']['debug']:
							logging.debug("[|-] puppet for windows installation started")
							#hostResults["installedStatus"] 	= 'installedStatus'
							hostResults["installedStatus"] 	= wmic.getInstalledSoftware(hostInfo['package_info']["osPackage"],hostInfo['package_info']['osPackageInstall'])
							#wmic.copyCoinfigurationFiles()
							#hostResults["softwareType"] 	= 'softwareType'
							hostResults["softwareType"] 	= wmic.getSoftwareType(hostInfo['package_info']["osPackage"])
							hostResults["softwareVersion"]	= wmic.getSoftwareVrsion()
						else:
							logging.info("[|-] puppet for windows installation started")
							hostResults["installedStatus"] 	= wmic.getInstalledSoftware(hostInfo['package_info']["osPackage"],hostInfo['package_info']['osPackageInstall'])

							#wmic.copyCoinfigurationFiles()
							hostResults["softwareType"] 	= wmic.getSoftwareType(hostInfo['package_info']["osPackage"])
							hostResults["softwareVersion"]	= wmic.getSoftwareVrsion()
					else: 
						logging.info("no value found for this key : [%s] \t value : [%s]"%(k,v))
					
				if hostInfo['info']['debug']: logging.debug("%s"%json.dumps(hostResults))
				host_information = json.dumps(hostResults).encode('utf-8')

				#'hostname|ipaddr|Caption|BuildNumber|OSArch|puppet_type|puppet_install_status
				#'svtmail|9.151.184.47|Microsoft Windows Server 2008 R2 Standard|7600|64-bit|TotalMemory|puppet_64-bit|status

				
				if hostInfo['info']['debug']: logging.debug("[|-]sending data %s|",host_information)
				else: logging.info("[|-] sending data results ")
				clientSocket.send(host_information)
				logging.info("[|++] Closing Client Connection |%s|",hostInfo['info']["address"])
				clientSocket.close()

				hostResults = {} 
			
			count = count+1
			break

		#logging.info("[+] Connection closed with: " + str(addr))
		

if __name__ == '__main__':
	Main()
