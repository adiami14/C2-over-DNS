# C2 over DNS Proof of Concept

This project was undertaken primarily for educational purposes. 
The key components of this project include:

- DNS docker environment environment:
  1. Two subnets - 192.168.3.0/24, 192.168.5.0/24
  2. Client / Agent - 192.168.3.70
  3. DNS Server (pi-hole) 192.168.3.3
  4. DNS Authoritative name-only  server (bind9) 192.168.3.100
  5. a C2 server - 192.168.5.70
- C2 over DNS tool to use.

**Setup**

```bash
git clone https://github.com/adiami14/C2-over-DNS.git
cd C2-over-DNS/enviroment/
./build_env.sh
```

type `1` and press `Enter` to build the environment for the project or for your own code. Inside the Docker containers, the  /data directory is the project directory shared with the host.

**Example**

inside the C2 server docker (`docker exec -it c2_server bash`)
```bash
./c2_dns.py M -iface eth0 -d c2.dns -ip 192.168.3.3 --debug 
```

Then, within the agent docker (`docker exec -it c2_client bash`)
```bash
./c2_dns.py A -iface eth0 -d c2.dns -ip 192.168.3.3 --debug
```

**Pi-hole docker**

The DNS server cache is disabled for development purposes. To re-enable it, access the DNS server Docker (`docker exec -it dns_server bash`).

Set the `cache-size` variable to 10000 if not already set and restart Pi-hole:

```bash
pihole restartdns
```

**bind9 docker**

This server functions as an authoritative-only domain name server with  one zone (command.control). It is invaluable for both learning and  development. Utilizing Wireshark, you can observe a portion of the DNS  resolution process when a query is sent by the client/agent.
