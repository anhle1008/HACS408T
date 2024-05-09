#!/usr/bin/env python3

from netaddr import *   # EUI(), IPAddress(), list()
import netaddr          # IPNetwork()
import netifaces        # interfaces(), ifaddresses()
import socket           # send(), recv(), connect(), etc.
import re               # regular expression
import binascii         # hexlify()
import json
import threading
import time

"""
    Construct an arp packet.
    Send arp request and receive arp reply.
    Take the MAC address from the received packet.
"""
def arp_packet(interface, dest_ip, source_mac, source_ip, results): 
    # Initialize and convert the type of all variables to bytes
    dest_mac_byte = b"\xff\xff\xff\xff\xff\xff"
    target_mac_byte = b"\x00\x00\x00\x00\x00\x00"
    source_mac_byte = EUI(source_mac).packed
    dest_ip_byte = IPAddress(dest_ip).packed
    source_ip_byte = IPAddress(source_ip).packed
    
    # Ethernet Header
    eth_header = dest_mac_byte      # Destination MAC
    eth_header += source_mac_byte   # Source MAC
    eth_header += b"\x08\x06"       # Ether type: ARP (0x0806)
    # Arp Data
    arp_data = b"\x00\x01"          # Hardware type: Ethernet
    arp_data += b"\x08\x00"         # Protocol type: IPv4
    arp_data += b"\x06"             # Hardware (MAC) size: 6
    arp_data += b"\x04"             # Protocol (IP) size: 4
    arp_data += b"\x00\x01"         # Operation: 1 - Request
    arp_data += source_mac_byte     # Sender MAC Address
    arp_data += source_ip_byte      # Sender IP Address
    arp_data += target_mac_byte     # Target MAC Address
    arp_data += dest_ip_byte	    # Target IP Address
    
    frame = eth_header + arp_data
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, socket.SOCK_RAW))
    sock.settimeout(1)
    try:    
        sock.send(frame)
        # print("[+] Send an ARP request to", dest_ip)
        time.sleep(0.5)
        response = sock.recv(1024)
        # Extract source MAC address from the received frame 
        if response[12:14] == b'\x08\x06' and response[20:22] == b'\x00\x02':
            target_source_mac = response[6:12]
            # return its hexadecimal representation as a bytes object
            hex_string = binascii.hexlify(target_source_mac)
            # join the pairs of 2 characters with a colon after decoding bytes to string
            target_source_mac = ':'.join(re.findall('..', hex_string.decode()))
            print("[+] RECEIVE a reply from", dest_ip)
            # add mac address to results
            results["machines"][interface][dest_ip] = {"mac": target_source_mac}
            print("[+] --> Add MAC address to results")
            return target_source_mac
    except socket.timeout:
        # print("No ARP reply received within the timeout")
        return None
    finally: 
        sock.close()

def tcp_scan(ip_addr, interface, results, port_range):
    results["machines"][interface][ip_addr]["tcp"] = {}
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:    
            con = sock.connect_ex((str(ip_addr), port)) 
            time.sleep(0.5)
            if con == 0:
                # DEBUG message
                print("[*] Port {} is OPEN in {}!".format(port, ip_addr))
                service = identify_services(port)
                results["machines"][interface][ip_addr]["tcp"][str(port)] = str(service)
                # DEBUG message
                print("[*] --> Add port {} to results".format(port))
        except:
            # DEBUG message
            # print("Port {} is closed in {}!".format(port, ip_addr))
            pass
        finally: 
            sock.close()

def multi_thread_tcp_scan(ip_addr, interface, results):
    print("[*] Port scan initiated in", ip_addr)
    # Initialize the number of threads 
    num_threads = 1000
    # Calculate the port ranges for each thread
    total_ports = 65535
    ports_per_thread = total_ports // num_threads
    port_ranges = [(i * ports_per_thread + 1, (i + 1) * ports_per_thread) 
                   for i in range(num_threads)]
    
    # Create threads
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=tcp_scan, 
                                  args=(ip_addr, interface, results, 
                                        range(port_ranges[i][0], port_ranges[i][1] + 1)))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to finish
    for thread in threads:
        thread.join()
    
    print("[*] Port scan complete in", ip_addr)

def identify_services(port_num):
    reference = {
        "7": "echo",
        "21": "ftp",
        "23": "telnet",
        "25": "smtp",
        "80" : "http",
    }
    return reference.get(port_num, "other")

def process(ip_addrs, interface, source_mac, source_ip, results):
    for dest_ip in ip_addrs:
        # Convert type IPAddress() to string
        dest_ip = str(dest_ip)
        target_source_mac = arp_packet(interface, dest_ip, source_mac, source_ip, results)
        if target_source_mac:
            multi_thread_tcp_scan(dest_ip, interface, results)
        # DEBUG message
        # print("[+] No ARP reply from", dest_ip)

def main():
    results = {"machines": {}}
    # Get the list of interface identifiers and remove local interfaces
    interfaces = netifaces.interfaces()
    interfaces.remove('lo')
    
    for interface in interfaces:
        # Get the addresses of the current interface 
        info = netifaces.ifaddresses(interface)
        # Get the IPv4 address of the current machine
        ip_addr = info[netifaces.AF_INET][0]['addr']	# AF_INET: normal Internet addresses
        # Get the MAC address of the current machine
        mac_addr = info[netifaces.AF_LINK][0]['addr']	# AF_LINK: link layer interface
        # Get the netmask of the current interface
        netmask = info[netifaces.AF_INET][0]['netmask']
	    # Write the network in CIDR notation
        network = netaddr.IPNetwork(ip_addr + '/' + netmask)
        
        print("###########################################################################")
        # DEBUG message
        print("Interface: {}, Source IP: {}, Source MAC: {}"
              .format(interface, ip_addr, mac_addr))
        # Add the info my machine in the current machine
        results["machines"][interface] = {ip_addr: {"mac": mac_addr}}
        # DEBUG message
        print("[+] --> Add my ip and mac addresses into results")
        multi_thread_tcp_scan(ip_addr, interface, results)
        
        # Generate a list of IP address in the network
        ip_addrs = list(network)
	    # Remove the addresses of network, broadcast, and current machine 
        ip_addrs.remove(network.network)
        ip_addrs.remove(network.broadcast)
        ip_addrs.remove(IPAddress(ip_addr))
        
        # Initialize the number of threads 
        num_threads = 1000
        # Calculate the number of IP addresses per thread
        ips_per_thread = len(ip_addrs) // num_threads
        ip_ranges = [(i * ips_per_thread, (i + 1) * ips_per_thread) 
                     for i in range(num_threads)]
        
        # Create threads
        threads = []
        for i in range(num_threads):
            # Create a thread for each destination IP address
            thread = threading.Thread(target=process, 
                                      args=(ip_addrs[ip_ranges[i][0]:ip_ranges[i][1]], 
                                            interface, mac_addr, ip_addr, results))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    # Write the results dictionary to a JSON file
    with open('results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("~~~The results.json is complete!~~~")

if __name__ == "__main__":
    main()
