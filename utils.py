from scapy.all import get_working_ifaces, get_working_if, get_if_hwaddr, get_if_addr
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
        print("Interface: {interface.name}\nMAC Address: {mac_addr}\nIP Address: {ip_addr}\n".format(interface.name, mac_addr, ip_addr))

def get_first_active_interface():
    """Get the first active network interface on the system."""
    return get_working_if()

def get_mac_address_of_interface(interface):
    """Get the MAC address of the specified interface."""
    try:
        return get_if_hwaddr(interface)
    except Exception as e:
        print("Could not get MAC address for interface {interface}: {e}".format(interface, e))
        return None

def get_ip_address_of_interface(interface):
    """Get the IP (v4) address of the specified interface."""
    try:
        return get_if_addr(interface)
    except Exception as e:
        print("Could not get IP address for interface {interface}: {e}".format(interface, e))
        return None
