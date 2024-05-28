from scapy.all import *
from scapy.layers.inet import IP
from logger import log_info, log_warning
from scapy.layers.http import HTTPRequest, TCP, Raw

class Forwarder:
    def __init__(self, interface, ip_attacker, ip_victim, ip_to_spoof):
        self.interface = interface
        self.ip_victim = ip_victim
        self.ip_attacker = ip_attacker
        self.ip_to_spoof = ip_to_spoof

    def strip(self):
        log_info("Starting packet forwarding")
        sniff(
            filter="tcp and port 80",
            prn=self._on_packet_to_server,
            iface=self.interface,
            count=0,
        )
        log_warning("Stopping packet forwarding")

    def _on_packet_to_server(self, packet):
        if not packet.haslayer(Raw):
            log_info("Ignoring packet without Raw layer")
            return
        
        # TODO: move these checks into sniff filter (also for DNS)
        from_victim = (packet[IP].src == self.ip_victim and packet[IP].dst == self.ip_attacker)
        from_server = (packet[IP].src == self.ip_to_spoof and packet[IP].dst == self.ip_attacker)

        if from_victim:
            log_info(
                "Received HTTP request for {} from {} with content {}".format(
                    packet[IP].dst, packet[IP].src, packet[Raw].load
                )
            )
            # TODO: Forward the packet to the server
            # 1. Extract data from packet
            # 2. Create a new packet with the extracted data destined for ip_to_spoof
            # 3. Send the new packet over HTTPS


        elif from_server:
            log_info(
                "Received HTTP response for {} from {} with content {}".format(
                    packet[IP].dst, packet[IP].src, packet[Raw].load
                )
            )
            # TODO: Forward the packet to the victim
            # 1. Extract data from packet (decrypt)
            # 2. Create a new packet with the extracted data destined for ip_victim
            # 3. Send the new packet over HTTP