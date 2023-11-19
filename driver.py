#!/bin/env python3
from dns_utils import *
from agent_c2_dns import C2_DNS_Agent
from server_c2_dns import C2_DNS_SERVER
import argparse
import logging
import sys
 
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Your program description')

    subparsers = parser.add_subparsers(required=True, help='Choose between master and agent', dest='mode')

    # Master parser
    master_parser = subparsers.add_parser("M", help='start as C2 Server -- waiting for beacon')
    master_parser.add_argument('-d', '--domain', required=False, help="domain name")
    master_parser.add_argument('-ip', '--DNS-server', required=True, help="DNS server IP")
    master_parser.add_argument('-iface', required=True, help="The name of the interface being used")
    master_parser.add_argument('--file', required=False, help='(Relevant only in Server - File to write the agent output in - default {file})')
    master_parser.add_argument('--debug', action='store_true', help="Enable debug mode")
    master_parser.add_argument('--max-payload-size', required=False)

    # Agent parser
    agent_parser = subparsers.add_parser('A', help='start as C2 agent -- send beacon every 5 sec and wait')
    agent_parser.add_argument('-d', '--domain', required=False, help="domain name")
    agent_parser.add_argument('-iface', required=True, help="The name of the interface being used")
    agent_parser.add_argument('-ip', '--server-ip', required=True, help="C2 server IP")
    agent_parser.add_argument('--debug', action='store_true', help="Enable debug mode")
    agent_parser.add_argument('--max-payload-size', required=False)

    args = parser.parse_args()
       
    log_level = logging.DEBUG if args.debug else logging.INFO
    domain = args.domain if args.domain else DOMAIN
    max_size = args.max_payload_size if args.max_payload_size else DEFAULT_MAX_PAYLOAD_SIZE
    iface = args.iface

    logger = Create_Logger_Object(log_level)
    logger.debug("[d] Running in debug mode\n")
    logger.info(f"[!] C2 domain name: {domain}")

    if args.mode == 'M':
        logger.info("[!] Running as server")
        file = args.file if args.file else '/dev/tty'
        logger.debug(f"[d] file: {file}")
        try:
            logger.info(f"[!] My ip: {get_my_ip_address(args.iface)}")
        except ValueError:
            logger.critical("[**] You must specify a valid interface name")
            sys.exit(1)
        server = C2_DNS_SERVER(domain, logger, iface, args.DNS_server, file=file, max_payload_size=max_size)
        server.run()
    else:
        logger.info("[!] Running as Agent")
        logger.info(f"[!] C2 IP address: {args.server_ip}")
        agent = C2_DNS_Agent(args.server_ip, domain, logger, iface, max_payload_size=max_size)
        agent.Activate()

    if iface:
        logger.info(f"[!] Interface: {iface}")
