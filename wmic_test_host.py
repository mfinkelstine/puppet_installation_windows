import socket, os 
import shutil
import wmi
import re
#import _winreg
import win32com.client
from _winreg import (HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, OpenKey, EnumValue, QueryValueEx) 
import sys, time
import json
import subprocess


ip 			= "<remote_ip>"
domain 		= "<domain_name>"
username 	= "<user_name>"
password 	= "<user_password>"
CSName = "" 
Caption = "" 
BuildNumber = "" 
OSArchitecture = ""

passedUsername = "%s\\%s" %(domain, username)
#from _winreg import *
#r = wmi.WMI(ip,namespace="root/default").StdRegProv
#result, names = r.EnumKey(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName=r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
#keyPath = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
#count = 0

wc = wmi.WMI( computer=ip, user=passedUsername, password=password) 

#while count <= len(names):
#    try:
#installed = [ IE40.service for service in range(0,len(names)) ]
 #utilizations = [cpu.LoadPercentage for cpu in c.Win32_Processor()]
#print "Installed [ %s ]" %installed
############################################################
## 

def getMSIinstallation():
	try:
		print "Trying regular Installation"
		wc.Win32_Product.Install (
			PackageLocation="\\\\jaffar32.eng.rtca\\installation_bin\\puppet-windows\\data\\puppet-3.7.1-x64.msi",
			AllUsers=True
			)
	except Exception, e:
		print "ERROR %s | %s" %(e,sys.exc_info()[0])
	
	try:
		print "Trying Admin Installation"
		wc.Win32_Product.Admin(
			PackageLocation="\\\\jaffar32.eng.rtca\\installation_bin\\puppet-windows\\data\\puppet-3.7.1.msi",
			#PackageName="puppet-3.7.1-x64.msi",
			TargetLocation="C:\puppet"
		)
	except Exception, e:
		print "ERROR %s | %s" %(e,sys.exc_info()[0])
		
	#print wc.Win32_Product.InstallState()

############################################################
## List all running processes in the Remote system.
def getWin32Process():
	for p in wc.Win32_Process():
		print p.ProcessID, p.Name
############################################################
## Whats running on startup and from where in your system?
def getStartUPCommand():
	for s in wc.Win32_StartupCommand ():
		print "[%s] %s <%s>" % (s.Location, s.Caption, s.Command)	
############################################################
## Show the IP and MAC addresses for IP-enabled network interfaces
def getIP_MAC_Addr():
	for interface in wc.Win32_NetworkAdapterConfiguration (IPEnabled=1):
		print interface.Description, interface.MACAddress
		for ip_address in interface.IPAddress:
			print ip_address
def getSoftwareInstalled():
	from _winreg import (HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, OpenKey, EnumValue, QueryValueEx)
	print "%s Software Installed list %s"%(5*"#",20*"-")
	reg = wmi.WMI(ip,namespace="root/default").StdRegProv
	result, names = reg.EnumKey (hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName=r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
	keyPath = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
	count = 0
	while count <= len(names):
		try:
			print names[count]
			path = keyPath + "\\" + names[count]
			key = OpenKey(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS)
			temp = QueryValueEx(key, 'DisplayName')
			display = str(temp[0])
			print names[count]+" -> "+display
			count += 1
		except:
			count += 1
			continue


############################################################
## List registry keys in your system
def getRegistry_keys():
	r = wmi.Registry ()
	result, names = r.EnumKey (
		hDefKey=_winreg.HKEY_LOCAL_MACHINE,
		sSubKeyName="Software"
		)
	for key in names:
		print key


def getServiceList():
	print "%s Service list [ %s ]"%(5*"#",20*"-")
	for s in wc.Win32_Service():
		if re.search("Puppet Agent", s.Caption):
			print s.Caption , s.State
			puppet_service=True



def WMIDateStringToDate(dtmDate):
    strDateTime = ""
    if (dtmDate[4] == 0):
        strDateTime = dtmDate[5] + '/'
    else:
        strDateTime = dtmDate[4] + dtmDate[5] + '/'
    if (dtmDate[6] == 0):
        strDateTime = strDateTime + dtmDate[7] + '/'
    else:
        strDateTime = strDateTime + dtmDate[6] + dtmDate[7] + '/'
        strDateTime = strDateTime + dtmDate[0] + dtmDate[1] + dtmDate[2] + dtmDate[3] + " " + dtmDate[8] + dtmDate[9] + ":" + dtmDate[10] + dtmDate[11] +':' + dtmDate[12] + dtmDate[13]
    return strDateTime

strComputer = "."
def getWinCaptionName():
	objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
	objSWbemServices = objWMIService.ConnectServer(ip,"root\CIMV2")
	colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_OperatingSystem")
	#print colItems

	for objItem in colItems: 
		print objItem
		#Caption 	= objItem.Caption
		#CSName 		= objItem.CSName
		#BuildType 	= objItem.BuildType
		#BuildNumber = objItem.BuildNumber
		#OSArchitecture = objItem.OSArchitecture
		
	#print "%s|%s|%s|%s|%s"%(CSName,ip,Caption,BuildNumber,OSArchitecture)
	
############################################################
## getWinArchitecture
def getWinArchitecture():
	for os in wc.Win32_OperatingSystem():
		arch = os.osarchitecture	
	return arch
	
def getCheckInstalledSoftware():
	objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
	objSWbemServices = objWMIService.ConnectServer(ip,"root\CIMV2")
	colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_Product")
	for objItem in colItems:
		if re.search("Puppet", objItem.Caption):
			print "Caption: ", objItem.Caption
			return True
	return False
	
def getInstalledSoftware():
	installed=False
	hostServiceList	=	{}
	objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
	objSWbemServices = objWMIService.ConnectServer(ip,"root\CIMV2")
	colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_Product")
	for objItem in colItems:
		print "%s" %("-"*20)
		if re.search("Puppet", objItem.Caption):
			installed=True
			print "Caption: ", objItem.Caption
			print "Description: ", objItem.description
		#print "Identifying Number: ", objItem.IdentifyingNumber
		#print "Install Date: ", objItem.InstallDate
		#print "Install Date 2: ", objItem.InstallDate2
		#print "Install Location: ", objItem.InstallLocation
		#print "Install State: ", objItem.InstallState
		#print "Name: ", objItem.Name
		#print "Package Cache: ", objItem.PackageCache
		#print "SKU Number: ", objItem.SKUNumber
		#print "Vendor: ", objItem.Vendor
		#print "Version: ", objItem.Version
		if objItem.Caption != None:
			hostServiceList.update({"Caption:" : objItem.Caption })
			print "Caption:" + ` objItem.Caption`
		if objItem.Description != None:
			hostServiceList.update({ "Description:" : objItem.Description })
			print "Description:" + ` objItem.Description`
		if objItem.IdentifyingNumber != None:
			hostServiceList.update({ "IdentifyingNumber:" : objItem.IdentifyingNumber })
			print "IdentifyingNumber:" + ` objItem.IdentifyingNumber`
		if objItem.InstallDate != None:
			print "InstallDate:" + ` objItem.InstallDate`
			hostServiceList.update({ "InstallDate:" : objItem.InstallDate })
		if objItem.InstallDate2 != None:
			print "InstallDate2:" + WMIDateStringToDate(objItem.InstallDate2)
			hostServiceList.update({"InstallDate2:" : WMIDateStringToDate(objItem.InstallDate2)})
		if objItem.InstallLocation != None:
			print "InstallLocation:" + ` objItem.InstallLocation`
			hostServiceList.update({"InstallLocation:" : objItem.InstallLocation })
		if objItem.InstallState != None:
			print "InstallState:" + ` objItem.InstallState`
			hostServiceList.update({"InstallState:" : objItem.InstallState})
		if objItem.Name != None:
			print "Name:" + ` objItem.Name`
			hostServiceList.update({ "Name:" : objItem.Name})
		if objItem.PackageCache != None:
			print "PackageCache:" + ` objItem.PackageCache`
			hostServiceList.update({"PackageCache:" : objItem.PackageCache})
		if objItem.SKUNumber != None:
			print "SKUNumber:" + ` objItem.SKUNumber`
			hostServiceList.update({"SKUNumber:" : objItem.SKUNumber})
		if objItem.Vendor != None:
			print "Vendor:" + ` objItem.Vendor`
			hostServiceList.update({"Vendor:" :objItem.Vendor})
		if objItem.Version != None:
			print "Version:" + ` objItem.Version`
			hostServiceList.update({"Version:" :objItem.Version})
		#print hostServiceList
	
	print "Installed Status : [ %s ]"%installed
	return installed

def createRemoteDirectory():
	print "Crating Remote directory"
	destPath = '\\\\'+ip+'\\puppet_installation\\'
	srcPath  = 'c:\\python_scripts\\puppet_installation\\'
	srcArchFiles = os.listdir(srcPath)
	
	try:
		os.makedirs(destPath)
	except OSError:
		print "Error unable to create directory"
		pass
	print "Copy files to remote machine"
	shutil.copytree(srcArchFiles,destPath,ignore=None)
		

def copy2remote():
	print ""
	
#def packageInstallation(CSName,OSArchitecture):
def packageInstallation():
	
	print "Starting installation procedure"
	# installation varibles
	puppet_PACAKGE_TYPE = ""
	host_name 				= 'SVTMAIL'
	logfile 				= 'logfile_'+host_name +'.txt'
	log_path				= 'c:\\'
	puppet_installation_log	= log_path+''+logfile
	arch = getWinArchitecture()
	print "os arch [ %s ] " %arch
	
	if re.search('64', arch):
		
		puppet_PACAKGE_TYPE 	= 'puppet-3.7.1-x64.msi'
	elif re.search('32', arch):
		puppet_PACAKGE_TYPE 	= 'puppet-3.7.1.msi'
	else:
		print "unknown OS Architecture for pacakge installation [ %s ]"%OSArchitecture
		
	puppet_installation_msi	='\\\\9.151.185.38\\puppet-windows\\data\\'+puppet_PACAKGE_TYPE
	puppet_INSTALLDIR		='INSTALLDIR=C:\\puppet'
	puppet_MASTER_SERVER	='PUPPET_MASTER_SERVER=puppet.xiv.ibm.com'
	
	hostadmin = 'SVTMAIL\Administrator'
	passwd 	  = 'abcd_1234'
	
	ps_exec='C:\PsTools\psexec.exe -s \\\\'+ip+' -u '+hostadmin+' -p '+passwd
	executible_msi = 'msiexec.exe /qn /norestart /l*vx '+puppet_installation_log+' /i '+puppet_installation_msi+' '+puppet_INSTALLDIR+' '+puppet_MASTER_SERVER
	print "ps_exec command :\n\t"+ps_exec
	print "msi inst command :\n\t"+executible_msi
	command = ps_exec+' '+executible_msi
	print "sending installation to "+host_name
	print "full command "+command
	
	install_status = cmd(command)
	
	if install_status == 0:
		print "installation finished successfully"
	else:
		print "installation failure"
		
	
	
def cmd(command):
	p = subprocess.Popen( command , stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell = True ) 
	return_code = p.wait()
	return return_code
	
installed=False	
getWinCaptionName()

#getWinArchitecture()
#getServiceList()
#getSoftwareInstalled()
#createRemoteDirectory()
getInstalledSoftware()

#if not getInstalledSoftware():
#	print "test installations"
#	packageInstallation()
#	while True:
#		print "wait for until installation finished"
#		time.sleep(3)
#		if getCheckInstalledSoftware():
#			print "Puppet installation have been finished successfully"
#	
#	print "Copying Necessary files to host"
	
	

#getMSIinstallation()



  
#installed = False
#for count in range(0,len(names)):
#	print names[count]
#	path = keyPath + "\\" + names[count]
#	key = OpenKey(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS)
#	temp = QueryValueEx(key, 'DisplayName')
#	display = str(temp[0])
#	print names[count]+" -> "+display
#	count += 1
#    except:
#        count += 1
#        continue

    #if 'Box, Inc.' == p.Vendor and p.Caption and 'Box Sync' in p.Caption:
    #    print 'Installed {}'.format(p.Version)


#r = wmi.Registry()
#result, names = wc.EnumKey (
#  hDefKey=_winreg.HKEY_LOCAL_MACHINE,
#  sSubKeyName="Software"
#)
#for key in names:
#  print key
#result = c.EnumKey(_winreg.HKEY_LOCAL_MACHINE, "SOFTWARE")
#for reg_key in result:
#    print reg_key
#	



#reg = wmi.WMI(computer=ip, user=passedUsername, password=password,namespace="root/default").StdRegProv 
#result, names = reg.EnumKey (hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName=r"Software\Microsoft\Windows\CurrentVersion\Uninstall") 
#keyPath = r"Software\Microsoft\Windows\CurrentVersion\Uninstall" 
#count = 0 
#while count <= len(names): 
#    try: 
#        print names[count] 
#        path = keyPath + "\\" + names[count] 
#        key = OpenKey(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS) 
#        temp = QueryValueEx(key, 'DisplayName') 
#        display = str(temp[0]) 
#        print names[count]+" -> "+display 
#        count += 1 
#    except: 
#        count += 1 
#        continue 
#	

#try:
	#wc.Win32_OperatingSystem(["OSArchitecture"])[0].OSArchitecture
#except IOError as (errno, strerror):
			#print "I/O error({0}): {1}".format(errno, strerror)
#except ValueError:
#			print "Could not convert data to an integer."
#except:
#except Exception, e:
	#print "ERROR %s | %s" %(e,sys.exc_info()[0])
	#d = sys.exc_info()[0]
	#matchObj = re.match("wmi.x_access_denied", sys.exc_info()[0])
#	if re.search("x_wmi_invalid_query", str(sys.exc_info()[0])):#
#		print " wmi invalid query:"
#	else:
#		print "Unexpected error:", sys.exc_info()[0]