from ctypes import *
from winpcapy import *
import time
import threading
import dpkt

def getAllDevs():
    errbuf=create_string_buffer(PCAP_ERRBUF_SIZE)
    alldevs=POINTER(pcap_if_t)()
    if (pcap_findalldevs(byref(alldevs),errbuf) == -1):
      print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
      return False
    dev=alldevs
    i=0
    devlist=[]
    while dev:
      i+=1
      #print dev.contents.name,'\n',dev.contents.description,'\n'
      #print dev.contents.flags, dev.contents.addresses
      devlist.append(dev.contents.name)
      devlist.append(dev.contents.description+'$')
      dev=dev.contents.next
    pcap_freealldevs(alldevs)
    return devlist


class Capture(threading.Thread):

  def __init__(self):
    threading.Thread.__init__(self)
    self.errbuf=create_string_buffer(PCAP_ERRBUF_SIZE)
    self.dev=None
    self.choice=0
    # self.filters=''
    self.catching_flag=True
    self.packet_count=0
    self.packet_heads=[]
    self.packet_datas=[]
    self.adhandle=None
    self.dumpfilepath=''
    self.MAXPACKETS=10000
    self.MAXSIZE=1024
    self.going_to_terminate=False
    self.waiting_for_signal=True #wait to finish dump packets

  def  setDev(self,dev):
    self.dev=dev

  def stop(self):
    if not self.catching_flag:
        return
    self.catching_flag=False
    self.waiting_for_signal=False
    print 'Stop the capture'

  def run(self):
    if self.adhandle==None:
      if self.dev==None:
        print "Set device first"
        return False
      dev_name=self.dev[0]
      dev_description=self.dev[1]
      self.adhandle=pcap_open_live(dev_name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,self.errbuf)
      if self.adhandle==None:
        print "Unable to open the adapter %s"%dev_name
        return False
    else:
      dev_name='File'
      dev_description='File'
    header = POINTER(pcap_pkthdr)()
    pkt_data = POINTER(c_ubyte)()
    #pcap_open(dev_name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,None,self.errbuf)
    print "Listen on %s\n%s"%(dev_name,dev_description)

    #set filters
    # if self.filters!='':
    #   fcode=bpf_program()
    #   NetMask=0xffffff
    #   if pcap_compile(self.adhandle,byref(fcode),self.filters,1,NetMask)<0:
    #     print "Compile filter error:Wrong Syntax"
    #     pcap_close(self.adhandle)
    #     return False
    #   if pcap_setfilter(self.adhandle,byref(fcode))<0:
    #     print "Setting filter error"
    #     pcap_close(self.adhandle)
    #     return False

    #set dump file or start to capture
      #print self.dumpfilepath,self.MAXSIZE,self.MAXPACKETS
    try:
      fp=pcap_dump_open(self.adhandle,"temp")
    except:
      raise "Can't creat temp file"
    if fp==None:
      print "Unable to start dump:%s"% pcap_geterr(self.adhandle)
      return False
    else:
      res=pcap_next_ex( self.adhandle, byref(header), byref(pkt_data))
      while res>=0 and self.catching_flag and self.packet_count < self.MAXPACKETS:
        local_tv_sec=header.contents.ts.tv_sec
        ltime=time.localtime(local_tv_sec)
        timestr=time.strftime("%H:%M:%S",ltime)
        packet=''
        for i in range(0,header.contents.len):
          packet+=chr(pkt_data[i])
        if packet != '':
          frame_head={
            "Frame Number":self.packet_count,
            "Arrive Time":timestr,
            "Interface Name":dev_name,
            "Frame Length":header.contents.len
            }
          pcap_dump(fp,header,pkt_data)#auto_dump
          self.packet_count+=1
          self.Analyze_packet(packet,frame_head)
        res=pcap_next_ex(self.adhandle,byref(header),byref(pkt_data))
      pcap_dump_flush(fp)
      wait_count=0
      while self.waiting_for_signal==True and wait_count<4:
          wait_count+=5
          print 'waiting to terminate'
          self.going_to_terminate=True
          time.sleep(0.1)
      if res==-1:
        print "Error reading the packets: %s\n", pcap_geterr(self.adhandle)
        return False
    pcap_close(self.adhandle)
    print 'OK,I quited'
    return True

  def Analyze_packet(self,packet,frame_head):
    ethernet=dpkt.ethernet.Ethernet(packet)
    ip=ethernet.data
    ip_proto=ip.data
    proto_head={"empty":0}
    proto_type='0x%04x'%ethernet.type
    proto_data=''
    protocol_types={
      dpkt.tcp.TCP:'TCP',
      dpkt.udp.UDP:'UDP',
      dpkt.icmp.ICMP:'ICMP',
      dpkt.arp.ARP:'ARP',
      dpkt.dhcp.DHCP:'DHCP',
      dpkt.dns.DNS:'DNS',
      dpkt.icmp6.ICMP6:'ICMP6',
      dpkt.igmp.IGMP:'IGMP',
      dpkt.ssl.SSL2:'SSL2',
      dpkt.ssl.TLS11_V:'TLS11_V',
      dpkt.ssl.TLS12_V:'TLS12_V',
      dpkt.ssl.TLS1_V:'TLS1_V',
      dpkt.tftp.TFTP:'TFtp',
      dpkt.igmp.IGMP:'IGMP', 
      type(''):'ARP', 
    }

    #ethernet
    temp=''
    for i in range(4):
      temp+=(ethernet.src).encode('hex')[i*2:i*2+2]+':'
    src=temp[:-1]
    temp=''
    for i in range(4):
      temp+=(ethernet.dst).encode('hex')[i*2:i*2+2]+':'
    dst=temp[:-1]
    ether_head={
    'src':src,
    'dst':dst
    }

    #ipv4
    if proto_type=='0x0800':
      ip_head={
        'Version':ip.v,
        'Header Length(bytes)':ip.hl*4,
        'DSF':ip.tos,
        'Total Length':ip.len,
        'Identification':ip.id,
        'Flags:Reserved bit':ip.rf,
        "Flags:Don't Fragment":ip.df,
        'Flags:More Fragment':ip.mf,
        'Fragment offset':ip.offset,
        'Time to Live':ip.ttl,
        'Protocol':protocol_types[type(ip_proto)],
        'Header Checksum':ip.sum,
        'Source':'%d.%d.%d.%d'%(ord(ip.src[:1]),ord(ip.src[1:2]),ord(ip.src[2:3]),ord(ip.src[-1:])),
        'Destination':'%d.%d.%d.%d'%(ord(ip.dst[:1]),ord(ip.dst[1:2]),ord(ip.dst[2:3]),ord(ip.dst[-1:])),
      }

      if protocol_types.has_key(type(ip_proto)):
        #udp
        if type(ip_proto)==dpkt.udp.UDP:
          proto_head={
            'Source port':ip_proto.sport,
            'Destination port':ip_proto.dport,
            'Length':ip_proto.ulen,
            'Checksum':ip_proto.sum,
          }
          proto_data=ip_proto.data
        #tcp
        elif type(ip_proto)==dpkt.tcp.TCP:
          proto_head={
            "Source port":ip_proto.sport,
            "Destination port":ip_proto.dport,
            "Sequence number":ip_proto.seq,
            "Acknowledgment number (if ACK set)":ip_proto.ack,
            "Data offset(int)":ip_proto.off,
            "Reserved":ip_proto.flags>>9&0x7,
            "NS":ip_proto.flags>>8&1,
            "CWR":ip_proto.flags>>7&1,
            "ECE":ip_proto.flags>>6&1,
            "URG":ip_proto.flags>>5&1,
            "ACK":ip_proto.flags>>4&1,
            "PSH":ip_proto.flags>>3&1,
            "RST":ip_proto.flags>>2&1,
            "SYN":ip_proto.flags>>1&1,
            "FIN":ip_proto.flags&1,
            "Window size":ip_proto.win,
            "Checksum":ip_proto.sum,
            "Urgent pointer":ip_proto.urp,
          }
          proto_data=ip_proto.data
          #igmp
        elif type(ip_proto)==dpkt.igmp.IGMP:
          proto_head={
            'Type':ip_proto.type,
            'Max Resp Time':ip_proto.maxresp,
            'Header Checksum':ip_proto.sum,
            'Multicast Address':'%d.%d.%d.%d'%(ip_proto.group&0xff000000,ip_proto.group&0xff0000,ip_proto.group&0xff00,ip_proto.group&0xff),
          }
        try:
            #http
            if ip_proto.dport == 80 and len(ip_proto.data) > 0:
              http = dpkt.http.Request(ip_proto.data)
              for i in http.__hdr_defaults__:
                  print i, ':', http.__hdr_defaults__[i]
        except:
            pass
      else:
        print "[!] Can't analyze this protocol"
    #ipv6
    elif proto_type=='0x86dd':
      src=''
      for i in range(len(ip.src)/2):
        temp=ip.src[i*2].encode('hex')+ip.src[i*2+1].encode('hex')
        if temp=='0000':
          src+=':'
        else:
          src+=temp+':'
      dst=''
      for i in range(len(ip.dst)/2):
        temp=ip.dst[i*2].encode('hex')+ip.dst[i*2+1].encode('hex')
        if temp=='0000':
          dst+=':'
        else:
          dst+=temp+':'
      ip_head={
        'Version':ip.v,
        'Traffic Class':ip._v_fc_flow>>20&0xff,
        'Flowlabel':ip._v_fc_flow&0xffffffffff,
        'Payload length':ip.plen,
        'Next header':ip.nxt,
        'Hop limit':ip.hlim,
        'Protocol':protocol_types[type(ip_proto)], 
        'Source':src,
        'Destination':dst,
      }

      if protocol_types.has_key(type(ip_proto)):
        #udp
        if type(ip_proto)==dpkt.udp.UDP:
          proto_head={
            'Source port':ip_proto.sport,
            'Destination port':ip_proto.dport,
            'Length':ip_proto.ulen,
            'Checksum':ip_proto.sum,
          }
          proto_data=ip_proto.data
        #tcp
        elif type(ip_proto)==dpkt.tcp.TCP:
          proto_head={
            "Source port":ip_proto.sport,
            "Destination port":ip_proto.dport,
            "Sequence number":ip_proto.seq,
            "Acknowledgment number (if ACK set)":ip_proto.ack,
            "Data offset":ip_proto.off,
            "Reserved":ip_proto.flags>>9&0x7,
            "NS":ip_proto.flags>>8&1,
            "CWR":ip_proto.flags>>7&1,
            "ECE":ip_proto.flags>>6&1,
            "URG":ip_proto.flags>>5&1,
            "ACK":ip_proto.flags>>4&1,
            "PSH":ip_proto.flags>>3&1,
            "RST":ip_proto.flags>>2&1,
            "SYN":ip_proto.flags>>1&1,
            "FIN":ip_proto.flags&1,
            "Window size":ip_proto.win,
            "Checksum":ip_proto.sum,
            "Urgent pointer":ip_proto.urp,
          }
          proto_data=ip_proto.data
          #icmp6
        elif type(ip_proto)==dpkt.icmp6.ICMP6:
          #print  `ip_proto`, dir(ip_proto), ip_proto.__hdr_fields__, ip_proto.__hdr__
          proto_head={}
          for field in ip_proto.__hdr_fields__:
            proto_head[field]=ip_proto[field]
        else:
            print "[!] Can't find type"
            print `ip`
      else:
        print "[!] Can't analyze this protocol"
    #arp
    elif proto_type=='0x0806':
      sip=''
      for i in ip.spa:
        sip+='%d.'%ord(i)
      tip=''
      for i in ip.tpa:
        tip+='%d.'%ord(i)
      sm=''
      for i in ip.sha:
        sm+='%02x:'%ord(i)
      tm=''
      for i in ip.tha:
        tm+='%02x:'%ord(i)
      ip_head={
        'Hardware type':ip.hrd,
        'Protocol':'ARP',
        'Hardware size':ip.hln,
        'Protocol size':ip.pln,
        'Opcode':ip.op,
        'Sender Mac':sm[:-1],
        'Sender IP':sip[:-1],
        'Target Mac':tm[:-1],
        'Target IP':tip[:-1],
      }
    else:
      print "Does't support this type"
      return False
      
    try:
        _proto='%s Protocol Header'%protocol_types[type(ip_proto)]
    except:
        print `ip`, '$'
        print type(ip_proto)
    
    self.packet_datas.append(proto_data)
    packet_head=[]
    packet_head.append(['Frame head', frame_head])
    packet_head.append(['Ethernet_head', ether_head])
    if proto_type=='0x0806':
        packet_head.append(['ARP', ip_head])
    else:
        packet_head.append(['IPv%d header'%ip.v, ip_head])
    packet_head.append([_proto, proto_head])
    self.packet_heads.append(packet_head)

  def setReadFile(self,path):
    source=create_string_buffer(PCAP_BUF_SIZE)
    if pcap_createsrcstr(source,PCAP_SRC_FILE,None,None,path,self.errbuf)!=0:
      print "Error creating source string:%s"%self.errbuf.value
    fp=pcap_open(
      source.value,
      65536,
      PCAP_OPENFLAG_PROMISCUOUS,
      1000,
      None,
      self.errbuf)
    try:
      fp.contents=fp.contents
    except:
      print "Unable to open the file %s,%s"%source.value,self.errbuf.value
      return False
    self.adhandle=fp

  def getFirstHead(self):
    return self.packet_heads[0]

  def removeFirstHead(self):
    self.packet_heads.remove(self.packet_heads[0])

  def getFirstData(self):
    return self.packet_datas[0]

  def removeFirstData(self):
    self.packet_datas.remove(self.packet_datas[0])
    
  def setDumpFile(self,path=''):
    self.dumpfilepath=path

  def setMaxsize(self,maxsize=1024):
    self.MAXSIZE=maxsize

  def setMaxpacets(self,maxpackets=20):
    if maxpackets>self.MAXPACKETS:
      print 'Too large maxpackets'
      return False
    self.MAXPACKETS=maxpackets
  
  # def setFilter(self,string=''):
  #   print string+'$'
  #   self.filters=string


def Useage():
  use="""Useage:
  -h    for this
  -l    list then select devices
  -C    number of packets you want to catch;Default=20
  -M    maxsize of file to dump;Default=1K
  -r    load a pcap file
  -d    dump result to file
  -f    filters
  [*]   ctrl+c stop catch
  [*]   if not set -d,the result will print
  [*]   if you use both -l and -f,-l will disable
  """
  print use

#def main(args):
#  cap=Capture()
#  dumpfilepath=None
#  readfilepath=None
#  choice=None
#  maxpackets=20
#
#  opts,args=getopt.gnu_getopt(args,'hC:M:r:d:f:l')
#  for o,a in opts:
#    if o=='-h':
#      Useage()
#    if o=='-f':
#      cap.setFilter(a)
#    if o=='-C':
#      maxpackets=int(a,10)
#      cap.setMaxpacets(maxpackets=maxpackets)
#    if o=='-l':
#      print '*********************************'
#      for i in range(len(cap.devlist)/2):
#        print i,'    ',cap.devlist[i*2+1]
#      print '*******************************************'
#      choice=int(raw_input('Select device serial:  '),10)
#      cap.setDev(choice)
#    if o=='-r':
#      readfilepath=a
#      cap.setReadFile(readfilepath)
#    if o=='-d':
#      dumpfilepath=a
#      cap.setDumpFile(path=dumpfilepath)
#    if o=='-M':
#      cap.setMaxsize(maxsize=int(a,10))
#  if readfilepath==None and choice==None:
#    print 'Wrong Option !'
#    Useage()
#    return 0
#
#  cap.start()
#  while cap.isAlive()==True:
#    time.sleep(0.15)
#  for packet in cap.packet_heads:
#    print "\n--------------------------------------------"
#    for info in packet:
#      print info[0]
#      for item in info[1]:
#        print "  ",item,":",info[1][item]
#    data=''
#    for i in cap.packet_data[packet[0][1]["Frame Number"]]:
#      data+=chr(i)
#    print data
#
#
#
#if __name__=='__main__':
#  main(sys.argv)
