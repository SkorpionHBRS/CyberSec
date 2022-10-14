from scapy.all import *

http_https = sniff(
        iface = 'eth0',
        filter = "tcp port 443 and tcp port 80", 
        count = 100)
wrpcap('http.pcap', http_https)

tcp = sniff(
        iface = 'eth0',
        filter = "tcp and tcp.flags.syn==1 and tcp.flags.ack==0",
        count = 100)
wrpcap('tcp.pcap', tcp)

dns = sniff(
        iface = 'eth0',
        filter = "dns",
        count = 100)
wrpcap('dns.pcap', dns)

rest = sniff(
        iface = 'eth0',
        count = 100)
wrpcap('rest.pcap', rest)
