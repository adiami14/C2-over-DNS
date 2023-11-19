#!/bin/python3
from scapy.all import *
from dns_utils import *

my_iface = "eth0"

def Wait_for_pkt(domain: bytes, src_ip: str):
    my_ip = get_my_ip_address(my_iface)
    print(f"My IP: {my_ip}")
    filter = f"udp"
    # print(filter)
    pkt = sniff(count=1, iface=my_iface)[0]
    pkt.show()
    
def handler(pkt: Packet):
    pkt.show()
    print(ls(pkt))

if '__main__' == __name__:
    # Wait_for_pkt(b"adiami.com", "192.168.3.100")
    sniff(filter=f'udp and host 192.168.3.254', prn=handler, iface=my_iface)