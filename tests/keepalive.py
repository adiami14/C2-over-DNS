#!/bin/env python3
from dns_utils import *
from time import sleep

ip = '192.168.3.3'
logger = Create_Logger_Object(logging.DEBUG)
comm = DNS_Comm(DOMAIN, 'eth0', logger,96,10, ip=ip)

def filter_func(pkt: Packet):
    if pkt.haslayer(IP) and pkt.haslayer(DNS):
      print(pkt[IP].src)
      if ip not in pkt[IP].src: return False
      print("inside IsMine:", pkt.summary())
      return comm.IsMine(pkt)
    
    return False

def keep_alive(req_pkt: Packet, logger: logging) -> Packet:
    send(req_pkt)
    while True:
        res_pkt = sniff(filter=f"src host {ip}", count=1, timeout=3)
        if res_pkt:
            res_pkt = res_pkt[0]
            if comm.IsMine(res_pkt): return res_pkt
            logger.debug(f"[d] {res_pkt.summary()}")
        Send(req_pkt)
        
        

while True:
    packet_handler = DNS_Packet(ip, DOMAIN)
    req_pkt = packet_handler.Craft_Requset_Packet(b"hello")
    # print("REQUEST")
    res_pkt = keep_alive(req_pkt, logger)
    print("RESPONSE")
    res_pkt.summary()
    sleep(3)
