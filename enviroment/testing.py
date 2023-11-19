#!/bin/env python3
from scapy.all import *
from dns_utils import *

my_iface = "br-2b4ddc39ab5b"

def Wait_for_pkt(domain: bytes, src_ip: str):
    my_ip = get_my_ip_address(my_iface)
    print(f"My IP: {my_ip}")
    filter = f"udp and host {src_ip}"
    # print(filter)
    pkt = sniff(count=1, iface=my_iface)[0]
    pkt.show()
    

if '__main__' == __name__:
    while True:
        Wait_for_pkt(b"adiami.com", "192.168.3.100")