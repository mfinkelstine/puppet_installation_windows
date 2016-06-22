
import wmi
import logging

domain 		= "ENG"
user 		= "meirfi"
password 	= "1q2w3e4r5t"

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s|%(funcName)-10s|%(levelname)-8s|%(message)s',                
                    datefmt='%m-%d %H:%M',
                    filename='windowsWmic.log',
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
					
class wmicInformation(object):
	
	def __init__(self,ip,domain,user,password,connection=None,debug=False):
		self.computer 	= ip
		self.domain 	= domain
		self.username 	= user
		self.password 	= password
		self.connection = connection
		self.debug 		= debug
		if self.debug:
			logging.info("[|-] WMIC Connection Information %s"%(10*"#"))
			logging.info("[|-]\tComputer    : %s"%self.computer)
			logging.info("[|-]\tDomain      : %s"%self.domain)
			logging.info("[|-]\tUsername    : %s"%self.username)
			logging.info("[|-]\tPassword    : %s"%self.password)
		self.makeConnection()
	#def getCredentials(self):
		
	def makeConnection(self):	
		if self.debug:
			logging.info( "[|-] initialize wmic connaction to [ %s ]" % self.computer)
		if self.domain:
			self.passedUsername = "%s\\%s" %(self.domain, self.username)
		else:
			self.passedUsername = self.username
		
		try:
			if self.debug:
				logging.info( "[|-] wmiConnection :\n\tcomputer=[%s],user=[%s],password=[%s]"%(self.computer,self.passedUsername,self.password))
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
	
	def getInstalledSoftware(self,application,install=None):
		installed = False
		reg = wmi.WMI(self.computer,namespace="root/default").StdRegProv
		result, names = reg.EnumKey(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName=r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
		keyPath = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
		logging.debug( "[|-] software name [ %s ] " %application)
		for count in range(0,len(names)):
			if self.debug: logging.debug( " installed software [ %s ] " %names[count])
			if names[count] == application:
				installed = True
		if install:
			os_arch = str(self.getArch())
			logging.info( "[|-] Running Installation software [ %s ] procedure on host [ %s ] os_arch [ %s ]" %(application,install , os_arch ))
			if re.search("64", os_arch):
				logging.info("[|-] installing [%s] for system architecture [ %s ]"%( application, os_arch))
				installation_results = self.getSoftwareInstallation("64")
			else:
				logging.info("[|-] installing [%s] for system architecture [ %s ]"%( application, os_arch))
				installation_results = self.getSoftwareInstallation("32")
				
		#if 
		#if installed: print "[ %s ] is installed on the system" %application
		return installation_results
		
	def getSoftwareInstallation (self,os_arch):
		
		hostFilesPath = "\\\\jaffar32\\installation_bin\\puppet-windows\\data\\"
		
		# local Puppet Directorys
		remotePath 			= "\\\\jaffar32\\installation_bin\\puppet-windows\\data"
		
		puppetPath			= "C:\\puppet"
		puppetBin 			= "C:\\puppet\\bin" 											# need to check if exist: and copy puppetagent.bat
		puppetWinPath 		= "C:\\Windows"
		puppetAppDataLab	= "C:\\ProgramData\\Application Data\\PuppetLabs\\puppet\\etc" 	# need to check if exist: and copy puppet.conf
		puppetProgramLab	= "C:\\ProgramData\\PuppetLabs\puppet\\etc"						# need to check if exist: and copy puppet.conf
		
		strOwnerMail = "itayr@il.ibm.com"
		strOwnerFile = "owner"
		
		strItcsClass = "4"
		strItcsFile  = "itcsgroup"
		
		# check if folder exist : C:\puppet
		#C:\Windows\system32\cmd.exe " /c date /T > C:\puppet\installdate "
		
		# check if folder exist : C:\ProgramData\PuppetLabs\puppet\etc
		# cp "data\puppet.conf" C:\ProgramData\PuppetLabs\puppet\etc
		
		# check folder exists C:\ProgramData\Application Data\PuppetLabs\puppet\etc
		# cp "data\puppet.conf" C:\ProgramData\Application Data\PuppetLabs\puppet\etc
	
		# check folder exists C:\puppet\bin
		# cp "data\puppetagent.bat" C:\puppet\bin
		#puppet files:
		
		hostPuppetBatchFile 	= "puppetagent.bat"
		hostPuppetConfFile  	= "puppet.conf"
		hostPuppetInstallDate 	= "installdate"
		
		
		
		if os_arch == "64":
			#C:\Windows\system32\cmd.exe C:\Windows\system32\msiexec.exe " /qb /i data\puppet-3.7.1-x64.msi INSTALLDIR="C:\puppet" PUPPET_MASTER_SERVER=puppet.xiv.ibm.com"
			logging.info("[|-] checking service  ")
			installPackage = "/qb /i " + remotePath+"\\puppet-3.7.1-x64.msi INSTALLDIR="+puppetPath
			if not self.getServiceStatus():
				logging.info("[|-] Starting installation procedure")
				self.packageInstallation(installPackage)
				return "installed"
			else:
				logging.info("[|-] Service already installed")
				return "already_installed"
		elif os_arch == "32":
			installPackage = remotePath+"\\puppet-3.7.1.msi INSTALLDIR="+puppetPath
			#print "installation package [ %s ] "%installPackage
			if not self.getServiceStatus():
				logging.info("[|-] Starting installation procedure")
				self.packageInstallation(installPackage)
				return "installed"
			else:
				logging.info("[|-] Service already installed")
				return "already_installed"
			#C:\Windows\system32\cmd.exe C:\Windows\system32\msiexec.exe " /qb /i data\puppet-3.7.1.msi INSTALLDIR="C:\puppet" PUPPET_MASTER_SERVER=puppet.xiv.ibm.com"
			#self.wmiConnection.Win32_Product.Install (
			#	PackageLocation="\\\\jaffar32\\installation_bin\\puppet-windows\\data\\puppet-3.7.1.msi INSTALLDIR=puppetPath",
			#	AllUsers=True
			#	)
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
	def packageInstallation(self,packageInstallation):
		print "installation package [ %s ] "%packageInstallation
		self.wmiConnection.Win32_Product.Install (
			PackageLocation=packageInstallation,
					AllUsers=True
					)
				
			
			
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
			#s.listen(1)
			return s
		except socket.error:
			print "unable to create socket"