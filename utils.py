from scapy.interfaces import get_working_ifaces, get_working_if
from scapy.all import get_if_hwaddr, get_if_addr
from scapy.all import ARP, Ether, srp

import os

def is_root():
    """Check if the script is running as root."""
    if os.name == 'nt':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0

def list_active_interfaces():
    """List all active network interfaces on the system."""
    interfaces = get_working_ifaces()
    for interface in interfaces:
        mac_addr = get_mac_address_of_interface(interface)
        ip_addr = get_ip_address_of_interface(interface)
        print("Interface: {}\nMAC Address: {}\nIP Address: {}\n".format(interface.name, mac_addr, ip_addr))

def get_first_active_interface():
    """Get the first active network interface on the system."""
    return get_working_if()

def get_mac_address_of_interface(interface):
    """Get the MAC address of the specified interface."""
    try:
        return get_if_hwaddr(interface)
    except Exception as e:
        print("Could not get MAC address for interface {}: {}".format(interface, e))
        return None

def get_ip_address_of_interface(interface):
    """Get the IP (v4) address of the specified interface."""
    try:
        return get_if_addr(interface)
    except Exception as e:
        print("Could not get IP address for interface {}: {}".format(interface, e))
        return None

def get_mac_address_from_ip(ip, interface):
    """Get the MAC address of the device with the specified IP address."""
    try:
        packet  = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        result = srp(packet, iface=interface, timeout=2, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        else:
            return None

    except Exception as e:
        print("Could not get MAC address for IP {}: {}".format(ip, e))
        return None