#packet_sniffer in python3
import struct
import socket

tab1='\t-'
tab2='\t\t-'
tab3='\t\t\t-'
tab4='\t\t\t\t-'

def main():
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data,addr=s.recvfrom(65535)
        dest_mac,source_mac,proto,data=ether_frame(raw_data)
        print ('\nEthernet Frame')
        print (tab1 +'Destination mac: ' + str(dest_mac) + ' Source mac: ' + str(source_mac) + ' protocol:' + str(proto))
        if proto == 8:
            version,ihl,ttl,protocol,src,dest,ip_data = ipv4_frame(data)
            print(tab1 + 'IPV4_frame :')
            print(tab2 + 'version : {} time_to_live : {} header length : {} '.format(version,ttl,ihl))
            print(tab2 + 'Protocol : {} source ip : {} destination ip : {}'.format(protocol,src,dest))
            if protocol == 1:
                 typ,code,checksum,icmp_data = icmp_frame(ip_data)
                 print(tab2 +'ICMP_frame :')
                 print(tab3 + 'icmp_type :'+str(typ)+' Code :'+str(code)+' Checksum :'+str(checksum))
            elif protocol == 17:
                 src_port,dest_port,udp_l,udp_data = udp_frame(ip_data)
                 print(tab2 + 'UDP_frame :')
                 print(tab3 + 'source port : {} dest_port : {} length : {}'.format(src_port,dest_port,udp_l))
            elif protocol == 6 :
                 src_port,dest_port,seq_no,ack_no,urg,ack,psh,rst,syn,fin,tcp_data = tcp_frame(ip_data)
                 print(tab2 + 'TCP_frame :')
                 print(tab3 + 'source port : {} dest_port : {}'.format(src_port,dest_port))
                 print(tab3 + 'sequence_no : {} acknowledgement_no : {}'.format(seq_no,ack_no))
                 print(tab3 + 'flags :')
                 print(tab4 + 'Urg_flag : ' +str(urg) +' Ack_flag : '+str(ack)+ ' Psh_flag : '+str(psh))
                 print(tab4 + 'Reset_flag : '+str(rst) + ' Syn_flag : '+str(syn) + ' fin_flag : '+str(fin))
            else :
                 #proper(tab3,data)
                 pass
        
        else:
            #proper(tab2,data)
            pass

#Unpacking Ethernet_frame
def ether_frame(data):
    dest_mac,source_mac,proto=struct.unpack('! 6s 6s H',data[:14])
    #print (dest_mac)
    return format_function(dest_mac),format_function(source_mac),socket.htons(proto),data[14:]

#function to format mac adresses properly (eg:- AA:BB:CC:DD:EE:FF)
def format_function(mac):
    new_mac=map('{:02x}'.format,mac)
    return ':'.join(new_mac).upper()

#Unpacking IPV4_frame
def ipv4_frame(data):
    version_ihl=data[0]
    version= version_ihl >> 4
    ihl= (version_ihl & 15) * 5
    ttl,proto,src,dest =struct.unpack('! 8x B B 2x 4s 4s ',data[:20])
    return version,ihl,ttl,proto,ip_format(src),ip_format(dest),data[ihl:]

#function to properly format ipv4 address (eg:- 127.0.0.4)
def ip_format(addr):
    new_addr=map(str,addr)
    return '.'.join(new_addr)

#Unpacking ICMP_frame
def icmp_frame(data):
    typ,code,checksum=struct.unpack('! B B H',data[:4])
    return typ,code,checksum,data[4:]

#Unpacking UDP_frame
def udp_frame(data):
    src_port,dest_port,udp_l = struct.unpack('! H H H 2x ',data[:8])
    return src_port,dest_port,udp_l,data[8:]

#Unpacking TCP_frame
def tcp_frame(data):
    src_port,dest_port,seq_no,ack_no,offset_reserved_flags=struct.unpack('! H H L L H' ,data[:14])
    offset=offset_reserved_flags >> 12
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1
    return src_port,dest_port,seq_no,ack_no,urg,ack,psh,rst,syn,fin,data[offset:]

#function for proper formatting of remaning data

main()

