#!/usr/bin/python
## get subprocess module 
import subprocess
import os
import time

ip 			= "9.151.184.47"
domain 		= "ENG"
username 	= "meirfi"
password 	= "1q2w3e4r5t"


passedUsername = "%s\\%s" %(domain, username)

def cmd( command ):
    #return subprocess.check_output( command, shell = True ) 
	p = subprocess.Popen( command , stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell = True ) 
	return_code = p.wait()
    #return subprocess.call( command, shell = True )
	print return_code


print "Starting installation procedure"
#psexec -i -d -s \\9.151.184.47 cmd /c cscript.exe "\\9.151.185.38\puppet_installation\puppet-windows\puppetdeploy.vbs"
##9.151.184.47
host_name = 'SVTMAIL'
#psexec -s \\9.151.184.47 -u "SVTMAIL\Administrator" -p "abcd_1234" msiexec.exe /qn /norestart /l*vx "c:\puppet_install.txt"  /i "\\9.151.185.38\puppet-windows\data\puppet-3.7.1-x64.msi" INSTALLDIR="C:\puppet" PUPPET_MASTER_SERVER="=puppet.xiv.ibm.com"
#msi_exec='msiexec.exe //qn //norestart /l*vx "c:\puppet_install.txt"  /i "\\9.151.185.38\puppet-windows\data\puppet-3.7.1-x64.msi" INSTALLDIR="C:\puppet" PUPPET_MASTER_SERVER="=puppet.xiv.ibm.com"'
logfile 				= 'logfile_'+host_name +'.txt'
#log_path			='\\\\9.151.185.38\\puppet-windows\\installation_logs\\'
log_path				= 'c:\\'
puppet_installation_log	= log_path+''+logfile
puppet_PACAKGE_TYPE 	= 'puppet-3.7.1-x64.msi'
puppet_installation_msi	='\\\\9.151.185.38\\puppet-windows\\data\\'+puppet_PACAKGE_TYPE
puppet_INSTALLDIR		='INSTALLDIR=C:\\puppet'
puppet_MASTER_SERVER	='PUPPET_MASTER_SERVER=puppet.xiv.ibm.com'
# host configuration:
hostadmin = 'SVTMAIL\Administrator'
passwd 	  = 'abcd_1234'
ps_exec='C:\PsTools\psexec.exe -s \\\\'+ip+' -u '+hostadmin+' -p '+passwd

# psexec -s \\9.151.184.47 -u "SVTMAIL\Administrator" -p "abcd_1234" 
  #msiexec.exe /qn /norestart /l*vx "c:\puppet_install.txt"  /i 
  #"\\9.151.185.38\puppet-windows\data\puppet-3.7.1-x64.msi" INSTALLDIR="c:\puppet"
  #PUPPET_MASTER_SERVER="puppet.xiv.ibm.com"
executible_msi = 'msiexec.exe /qn /norestart /l*vx '+puppet_installation_log+' /i '+puppet_installation_msi+' '+puppet_INSTALLDIR+' '+puppet_MASTER_SERVER
print "ps_exec command :\n\t" +ps_exec
print "msi inst command :\n\t"+executible_msi
command = ps_exec+' '+executible_msi
print "sending installation to "+host_name
print "full command "+command

cmd( command )

 