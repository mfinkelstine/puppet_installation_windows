import wmi

#
# Using wmi module before 1.0rc3
#
connection = wmi.connect_server (
  server="other_machine",
  user="tim",
  password="secret"
)
c = wmi.WMI (wmi=connection)

#
# Using wmi module at least 1.0rc3
#
c = wmi.WMI (
  computer="other_machine",
  user="tim",
  password="secret"
)