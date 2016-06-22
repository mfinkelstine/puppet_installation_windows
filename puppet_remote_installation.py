import wmi

connection = wmi.connect_server (
  server="vlw189.eng.rtca",
  user="meirfi",
  password="1q2w3e4r5t"
)
c = wmi.WMI(wmi=connection)

for opsys in c.Win32_OperatingSystem ():
  print opsys

systemArch  = c.Win32_Processor.Caprion
 
print systemArch
 #for tpc in c.Win32_Processor():
 # print tpc

#result = c.Win32_Product.Install(
#    #PackageLocation="\\\\mypc\\tmp\\python-3.4.1.msi",
#    PackageLocation="\\\\jaffar32\\installation_bin\\puppet-windows\\puppetdeploy.vbs",
#    AllUsers=True
#)
#print( result)