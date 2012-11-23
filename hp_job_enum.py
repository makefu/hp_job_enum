from pysnmp.entity.rfc3413.oneliner import cmdgen
import time

def main(hostname,options):

  cg = cmdgen.CommandGenerator()
  comm_data = cmdgen.CommunityData(options.community)
  transport = cmdgen.UdpTransportTarget((hostname, options.port))
  from binascii import unhexlify

  def snmp_get(oid):
    ei,es,ein,result = cg.getCmd(comm_data,transport,oid)
    return result

  oidtable = {"id": "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.2.%s.0",
      "domain":"1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.3.%s.0",
      "time":"1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.4.%s.0",
      "tool": "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.6.%s.0",
      "tool_exe": "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.7.%s.0",
      "user":"1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.8.%s.0", 
      "doc": "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.1.%s.0",
      "pages": "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.12.%s.0",
      "size": "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.14.%s.0",
       }

  # ENUM OID
  def splitq(o):
    try:
      return str(o).split("=")[1]
    except:
      return "N/A"
  enum_oid = (1,3,6,1,4,1,11,2,3,9,4,2,1,1,6,5,23,1)
  errIndication, errStatus, errIndex, result  = cg.nextCmd(comm_data,transport,enum_oid)
  if errIndication:
    print ("cannot connect to %s" %hostname)
  for obj in result:
    data = {}
    ident = str(obj[0][0]).split(".")[-2]

    for desc,oid in oidtable.items():
      data[desc] =  snmp_get(oid% ident)[0][1]
    #print ("File: %s with %s pages" % ( unicode(str(data["doc"]),"utf-8"), int(data["pages"])))
    print ("File: %s with %s pages" % ( unicode(str(data["doc"]),"latin-1"), int(data["pages"])))
    try:
      print ("Date: %s" % time.strftime("%d.%b.%Y %H:%M:%S",time.strptime(splitq(data["time"]),"%Y%m%d%H%M%S")))
    except:
      print ("Date: N/A")
    print ("User: %s\\%s from %s"%(splitq(data["domain"]),splitq(data["user"]),splitq(data["id"])))
    print ("Tool: %s (%s)" %(splitq(data["tool"]),splitq(data["tool_exe"])))
    print ("")

if __name__ == "__main__":
  from optparse import OptionParser
  from sys import exit
  usage = "usage: %prog [options] HOSTNAME"
  parser = OptionParser(usage=usage)
  parser.add_option("-c","--community",dest="community",help="SNMP community string",default="public",metavar="COMMUNITY")
  parser.add_option("-p","--port",dest="port",help="SNMP Port",default=161,type="int",metavar="PORT")
  (options, args) = parser.parse_args()
  if not args:
    parser.print_help()
    exit(1)
  main(args[0],options)
