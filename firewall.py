#!/usr/bin/env python

import socket
import struct
import fnmatch

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext
	self.ipListStart=[]
        self.ipListEnding=[]
        self.countries=[]
	self.rules=[]
        self.decision=[]
	self.closest_index=None
	self.closest_number=None

        # TODO: Load the firewall rules (from rule_filename) here.
	f1=open(config['rule'],'r')
        for line in f1:
	  if line[0] !='\n' and line[0] !='%':
		line=line.strip('\n')
	  	rules=line.split(' ')
          	if len(rules)==4:
	    	    self.rules.append((rules[1],rules[2],rules[3]))
	    	    self.decision.append(rules[0])
          	if len(rules)==3:
                    self.rules.append((rules[1],rules[2]))
            	    self.decision.append(rules[0])
	self.rules.reverse()
	self.decision.reverse()
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
	f=open('geoipdb.txt','r')
        s=struct.Struct('!L')
        for line in f:
	  line=line.strip('\n')
	  ranges=line.split(' ')
          binary=socket.inet_aton(ranges[0])
          integer=s.unpack(binary)[0]
          self.ipListStart.append(integer)
          binary=socket.inet_aton(ranges[1])
          integer=s.unpack(binary)[0]
          self.ipListEnding.append(integer)
          self.countries.append(ranges[2])
          
        # TODO: Also do some initialization if needed.

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        if pkt_dir==PKT_DIR_INCOMING:
		destination='incoming'
	if pkt_dir==PKT_DIR_OUTGOING:
		destination='outgoing'
	info=self.interpret_packet(pkt,destination)
	if info=='unknown':
		if destination=='incoming':
			self.iface_int.send_ip_packet(pkt)
		else:
			self.iface_ext.send_ip_packet(pkt)
	if info !=None:
		i=0
		for rule in self.rules:
			decision=self.matcher(info,rule)
			if decision=='match':
				if self.decision[i]=='pass' and destination=='incoming':
					self.iface_int.send_ip_packet(pkt)
					return
				elif self.decision[i]=='pass' and destination=='outgoing':
					self.iface_ext.send_ip_packet(pkt)
					return
				if self.decision[i]=='drop':
					print info
					return
			i+=1
		if destination=='incoming':
			self.iface_int.send_ip_packet(pkt)
		else:
			self.iface_ext.send_ip_packet(pkt)



    def range_matching(self,port,ranges):
	interval=ranges.split('-')
	port=int(port)
	lower=int(interval[0])
	upper=int(interval[1])
	if port<=upper and port>=lower:
		return 1
	return 0
    def country_matching(self,ipAddress,code):
	country=self.country_lookup(ipAddress)
	if country != None and country.lower()==code.lower():
		return 1
	return 0
    def ip_prefix_matching(self,ipAddress,ipPrefix):
	prefix=ipPrefix.split("/")
	binary1=socket.inet_aton(ipAddress)
	integer2=struct.unpack('!L',binary1)[0]
	binary=socket.inet_aton(prefix[0])
        integer=struct.unpack('!L',binary)[0]
	integer1=int(prefix[1])
	if integer2>>integer1 == integer>>integer1:
		return 1
	return 0
	
    def matcher(self,details,rule):
	if details[0]==rule[0] or (details[0]=='dns' and rule[0]=='udp') :
		if rule[0]=='dns' and details[0]=='dns':
			if fnmatch.fnmatch(details[3].lower(),rule[1].lower()):
				return 'match'
		if rule[1]=='any':
			if rule[2]=='any':
				return 'match'
			if '-' in rule[2]:
				port_match=self.range_matching(details[2],rule[2])
				if port_match:
				    return 'match'
			else:
			        if rule[2]==details[2]:
				    return 'match'
		if len(rule[1])==2:
			match=self.country_matching(details[1],rule[1])
			if match:
			    if rule[2]=='any':
				return 'match'
			    if '-' in rule[2]:
				port_match=self.range_matching(details[2],rule[2])
				if port_match:
				    return 'match'
			    else:
				if rule[2]==details[2]:
				    return 'match'
		if '/' in rule[1]:
			prefix_match=self.ip_prefix_matching(details[1],rule[1])
			if prefix_match:
				if rule[2]=='any':
					return 'match'
				if '-' in rule[2]:
					port_match=self.range_matching(details[2],rule[2])
					if port_match:
				    		return 'match'
			    	else:
				    if rule[2]==details[2]:
				        return 'match'
		if rule[1]==details[1]:
			if rule[2]=='any':
				return 'match'
			if '-' in rule[2]:
			    port_match=self.range_matching(details[2],rule[2])
			    if port_match:
				return 'match'
			else:
			    if rule[2]==details[2]:
				return 'match'

	return 'no match'
    # TODO: You can add more methods as you want.
    def interpret_packet(self,packet,direction):
	if len(packet)<20:
		return None
        length=struct.unpack('!B',packet[0])[0]& 0xf
	length=length*4
	total_length=struct.unpack_from('!H',packet,2)[0]
	if len(packet) != total_length:
		return None
	protocol=struct.unpack('!B',packet[9])[0]
	src_ip=packet[12:16]
	dst_ip=packet[16:20]
	protocol_name=self.get_protocol(protocol)
	if protocol_name=='tcp' or protocol_name=='udp':
		if protocol_name=='tcp':
			if len(packet[length:])<20:
				return None
		if protocol_name=='udp':
			if len(packet[length:])<8:
				return None
		if direction=='incoming':
			port_number=packet[length:length+2]
			ip_address=src_ip
		else:
			port_number=packet[length+2:length+4]
			ip_address=dst_ip
		ip_address=socket.inet_ntoa(ip_address)
		port_number=struct.unpack('!H',port_number)[0]
		port_number=str(port_number)
		if protocol_name=='udp' and port_number=='53' and direction=='outgoing':
			dns_start=length+8
			if len(packet[length+8:])<12:
				return None
			qd_count=struct.unpack('!H',packet[dns_start+4:dns_start+6])[0]
			if qd_count==1:
				dns_data=dns_start+12
				position=dns_data
				qname_list=[]
				while position <=(len(packet)-1) and ord(packet[position])!=0:
					length_index=ord(packet[position])
					qname_list.append(packet[position+1:position+1+length_index])
					position=position+1+length_index
				if ord(packet[position])!=0:
					return None
				if len(packet[position+1:])<4:
					return None
				qname='.'.join(qname_list)
				qtype=struct.unpack('!H',packet[position+1:position+3])[0]
				qclass=struct.unpack('!H',packet[position+3:position+5])[0]
				
				if (qtype==1 or qtype==28) and qclass==1:
					protocol_name='dns'
					return (protocol_name,ip_address,port_number,qname)
				else:
					return (protocol_name,ip_address,port_number)
			else:
				return (protocol_name,ip_address,port_number)
		else:
			return (protocol_name,ip_address,port_number)	 
	elif protocol_name=='icmp':
		if len(packet[length:])<8:
			return None
		icmp_type=str(ord(packet[length]))
		if direction=='incoming':
			ip_address=src_ip
		else:
			ip_address=dst_ip
		ip_address=socket.inet_ntoa(ip_address)
		return (protocol_name,ip_address,icmp_type)
	else:
		return 'unknown'
	
		
  
    def get_protocol(self,prtcl):
	if prtcl==1:
	  return 'icmp'
	if prtcl==17:
	  return 'udp'
	if prtcl==6:
	  return 'tcp'
        return 'unknown'

    def binary_search(self,ipList,target,lower,upper):
        middle=(lower+upper)/2
	if lower>upper:
		return self.closest_number
	if ipList[middle]==target:
		return middle
	elif ipList[middle]<target:
		self.closest_number=middle
		return self.binary_search(ipList,target,middle+1,upper)
        else:
		return self.binary_search(ipList,target,lower,middle-1)

    def country_lookup(self,ipAddress):
	self.closest_number=None
	binary=socket.inet_aton(ipAddress)
	ip_address=struct.unpack('!L',binary)[0]
	position=self.binary_search(self.ipListStart,ip_address,0,len(self.ipListStart))
	if position==None:
		return None
	if self.ipListEnding[position]>ip_address and self.ipListStart[position]<ip_address:
		return self.countries[position]
        else:
		return None
	
	
	
# TODO: You may want to add more classes/functions as well.
