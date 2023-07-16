try:
    from colorama import Fore
    import time
    import os
    import platform
    import socket
    import nmap
    import asyncio
    import re
    import concurrent.futures
    from scapy.all import sniff, Raw, send
    from scapy.layers.inet import IP, TCP
    import subprocess
    import threading
    import ipaddress
    import signal
    import pcapy


except ModuleNotFoundError as err:
    print(err, 'please install it')

ops = platform.system().lower()
if 'windows' in ops:
    os.system('cls')

else:
    os.system('clear')

ops = platform.system().lower()

_version_ = 1.0


# scapy.conf.checkIPaddr = False

# print(Fore.WHITE, '')

def device_scan():
    def ping(ip):
        # Send an ICMP echo request (ping) to the IP address
        if platform.system().lower() == "windows":
            # Use 'ping' command for Windows
            command = ['ping', '-n', '1', '-w', '1000', str(ip)]
        else:
            # Use 'ping' command for Linux/Mac
            command = ['ping', '-c', '1', '-W', '1', str(ip)]

        # Execute the ping command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        # Check the return code to determine if the device is online
        if result.returncode == 0:
            return str(ip)

        return None

    def scan_devices(network):
        # Convert the network string to an IP network object
        try:
            ip_network = ipaddress.IPv4Network(network)
        except ValueError as e:
            print("Invalid network:", e)
            return

        # Create a list to store the online devices
        online_devices = []

        # Scan the IP addresses in the network using multiple threads
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit ping tasks for each IP address in the network
            ping_tasks = [executor.submit(ping, ip) for ip in ip_network.hosts()]

            # Wait for the ping tasks to complete
            for future in concurrent.futures.as_completed(ping_tasks):
                result = future.result()
                if result:
                    online_devices.append(result)

        # Print the online devices
        print("Online devices in the network:")
        for device in online_devices:
            print(device)
            

    def main_scan():
        # Get the network range from the user
        network = input("Enter the network range (e.g., 192.168.1.0/24): ")

        # Scan the devices in the network
        scan_devices(network)

    if __name__ == '__main__':
        main_scan()

def net_scan():
    import pywifi
    from pywifi import const

    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming there is only one wireless interface

    iface.scan()
    results = iface.scan_results()

    for result in results:
        print("SSID:", result.ssid)
        print("Signal Strength:", result.signal)
        print("BSSID:", result.bssid)
        #print("Encryption:", result.encryption)
        print("---------------")


def get_domain_name(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return None


def get_domain_name(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return None


def website_visited(ip_address):
    import requests
    domain_name = get_domain_name(ip_address)
    if domain_name:
        print(f"IP: {ip_address}\tDomain: {domain_name}")
        try:
            response = requests.get(f"http://{domain_name}")
            print(f"Response Code: {response.status_code}")
            # Process the response further if needed
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    else:
        print(f"IP: {ip_address}\tNo domain found")


def scan_cctv_cameras(network, ports):
    # Create an instance of the PortScanner class
    scanner = nmap.PortScanner()

    # Convert the ports to a comma-separated string
    port_range = ','.join(str(port) for port in ports)

    # Run the scan on the specified network and port range
    scanner.scan(network, arguments='--open -p ' + port_range)

    # Iterate over the scan results and filter for open ports
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            port_info = scanner[host][protocol]
            for port in port_info.keys():
                state = port_info[port]['state']
                if state == 'open':
                    print(f"CCTV Camera found at {host}:{port}")


def scan_port(args):
    target_ip, port = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(Fore.GREEN, f"Port {port} is open on {target_ip}")
        s.close()
    except Exception as e:
        print(Fore.RED, f"An error occurred while scanning port {port}: {str(e)}")


def port_scanner(target_ip, start_port, end_port):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        port_range = range(start_port, end_port + 1)
        executor.map(scan_port, [(target_ip, port) for port in port_range])
    return True


def packetSender(message, destination_port, destination_ip, packet_size):
    from scapy.all import send
    from scapy.layers.inet import IP, TCP

    def send_message(destination_ip, destination_port, message):
        # Craft the packet with the desired message and packet size
        packet = IP(dst=destination_ip) / TCP(dport=destination_port) / (message * packet_size)

        # Send the packet
        send(packet)


    send_message(destination_ip, destination_port, message)



def print_packet(packet):
    # Extract source and destination IP addresses
    source_ip = packet.ip.src
    dest_ip = packet.ip.dst

    print(f"Source IP: {source_ip}\t Destination IP: {dest_ip}")

def read_packets(ip_address, adapter):
    import struct
    import pyshark
    # Set the network interface to capture packets on
    interface = adapter

    # Set the filter expression to capture packets from a specific IP address
    filter_expression = f"src host {ip_address}"

    # Create a PyShark capture object
    capture = pyshark.LiveCapture(interface=interface, display_filter=filter_expression)

    # Start capturing packets
    for packet in capture.sniff_continuously():
        print_packet(packet)

def displayHelp():
    print("""
          option  :  command
    - Port scanner: port {ip} {start port}-{end port}
    - Packet sender: send
    - Device scan: scan lan
    - Network scan: scan network
    - CCTV scanner: cctv
    - Show this message: help
    - Reset terminal: clear

    """)



def clear():
    if 'windows' in ops:
        os.system('cls')
        main()
        
    else:
        os.system('clear')
        main()
    
def main():


    print(Fore.BLUE, '''             

                                                                    ▓▓▓▓▓▓▓▓▒▒
                                                               ▒▒▓▓▒▒      ▒▒▓▓░░          
                                                              ▓▓▒▒    ▓▓▓▓▓▓    ▓▓▒▒      
                                                                  ▓▓▒▒      ▒▒▓▓         
                                                                ▓▓    ▓▓▓▓▓▓  ░░░░        
                                                                    ▓▓▓    ▓░░               
                                                                        ▓░''')
    print(Fore.RED, '''            ▒▒██▓▓▓▓▓▓▓▓████▒▒░░                                                                                     
            ▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████████▒▒                                                                                                             
          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████▒▒                            ▓▓                                              
          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██░░              ▒▒          ▓▓                                              
        ▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓▓        ▒▒        ▓▓                                              
        ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒  ██▓▓▒▒      ▓▓      ▒▒▒▒                                              
      ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░    ▒▒▒▒    ▒▒      ▒▒          ░░▒▒▓▓░░                              
      ▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓      ▒▒▒▒  ▒▒      ▒▒        ▒▒▒▒    ░░                              
      ▓▓▓▓▓▓▓▓▓▓▓▓▒▒  ▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓      ▓▓▒▒▓▓▓▓    ▒▒      ▒▒                                        
      ▓▓▓▓▓▓▒▒  ░░▒▒▓▓▓▓▒▒▒▒▓▓▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒    ▒▒▓▓░░▒▒  ░░▓▓▒▒░░▓▓▒▒                                        
      ▓▓░░  ░░▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░    ▒▒▓▓▓▓▓▓▓▓      ▒▒  ▓▓▒▒▒▒▓▓  ░░▒▒                              ░░▓▓▓▓░░    
        ▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▒▒▓▓▒▒          ▒▒▓▓▓▓▓▓▓▓  ░░▓▓▒▒▒▒▓▓  ▓▓  ▓▓░░                              ▓▓▓▓▒▒▓▓    
          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                      ▒▒▓▓▒▒▓▓▓▓▓▓  ▒▒▓▓  ▓▓  ▓▓  ▓▓                              ▓▓▓▓▒▒▓▓▒▒▒▒  
                                                      ▓▓▓▓▓▓██░░░░██▒▒██░░██░░▓▓                            ▒▒▒▒▒▒▓▓▓▓▓▓██  
                                                    ░░▒▒██████▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░    ▓▓▓▓▓▓▓▓▒▒▒▒▓▓  
                                                  ▒▒  ▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▓▓░░
                                          ░░░░  ▓▓▒▒▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓░░
                                              ▒▒░░▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▓▓▓▓
                                              ▒▒▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓
                                              ░░░░▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓░░
                                          ░░░░  ▓▓▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▓▓▓▓░░
                                                  ▓▓    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒  
                                                    ░░▓▓▓▓████▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓      ░░▒▒  ░░░░  ░░          ▒▒▒▒▒▒▒▒▒▒▒▒▓▓░░
                                                    ▓▓▓▓▓▓▓▓▒▒  ░░▓▓  ▓▓  ▓▓░░▓▓                            ▒▒░░▒▒▒▒▒▒▓▓▒▒  
        ░░░░                                      ▓▓▓▓▓▓▓▓▓▓▒▒  ▒▒▓▓  ▓▓  ▓▓  ▒▒                              ▒▒░░▒▒▒▒▒▒▒▒  
        ▒▒▒▒▓▓▓▓▓▓▓▓▓▓██▒▒                        ▒▒▓▓▒▒▓▓░░    ▓▓▒▒▒▒▓▓  ▓▓  ▓▓░░                            ░░▒▒▒▒▒▒▓▓    
      ▓▓▒▒▓▓▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▒▒        ▒▒▒▒▓▓▓▓▓▓      ▒▒  ▓▓▓▓▒▒▓▓  ░░▒▒                                ▒▒▒▒      
      ▒▒▒▒▓▓▒▒▓▓▒▒▒▒▒▒▒▒▒▒▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▒▒▓▓▓▓▓▓      ░░▒▒  ▒▒░░░░▓▓▒▒  ▓▓░░                                        
      ▓▓▒▒▒▒▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▒▒▒▒▓▓▒▒      ▓▓▓▓▒▒▒▒  ░░▒▒  ░░▓▓▓▓▒▒░░░░                                  
      ░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓        ▒▒░░▒▒▒▒    ▒▒      ▒▒░░                                      
        ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▓▓▓▓▒▒▓▓▓▓▒▒▒▒▒▒▒▒▓▓▓▓▓▓        ▒▒▒▒  ▓▓      ▓▓        ▒▒▒▒░░  ▓▓                              
        ▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▓▓▒▒▓▓▓▓      ░░▒▒▒▒    ▒▒      ▒▒░░          ▒▒▓▓                                
          ▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ██▓▓▒▒      ▓▓      ▒▒▒▒                                              
            ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██      ░░░░      ░░▒▒        ▓▓                                              
            ░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██                  ▒▒          ▓▓░░                                            
                ░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓                                  ░░                                              
                    ░░▓▓▓▓██▓▓▓▓▓▓██▓▓                                                                                      

    ''')
    print(Fore.GREEN, f'''
    A lobster: Network Hacking edition :o
    Author: A Lobster
    github: https://github.com/ALobster
    Current version: {_version_}''')
    # global target_ip
    while True:
        print(Fore.WHITE, '')
        command = input("lobster>")
        # print(command[0:4])
        if command[0:4] == 'cctv':
            network = command[5:17]
            ports = [int(port) for port in command[18:].split(',')]
            scan_cctv_cameras(network, ports)
        elif command[0:4] == 'port':
            target_ip, port_range = command[5:].split()
            start_port, end_port = map(int, port_range.split('-'))
            while True:
                result = port_scanner(target_ip, start_port, end_port)
                if result:
                    break


        elif command[0:4] == 'send':
            message = input('Enter message: ')
            size = int(input('Enter packet size: '))
            destination_port = int(input('Enter port: '))
            destination_ip = input("Enter destination IP: ")
            packetSender(message, destination_port, destination_ip, size)

        elif command[0:3] == 'web':
            website_visited(command[4:])

        elif command[0:4] == 'scan':
            if command[5:] == 'network':
                net_scan()
            elif command[5:] == 'lan':
                for i in range(256):
                    ip_address = f"192.168.1.{i}"
                    domain_name = get_domain_name(ip_address)

                    if domain_name:
                        print(Fore.GREEN, f"The IP address {ip_address} is associated with the domain: {domain_name}")
                    else:
                        print(Fore.RED, f'The IP address {ip_address} does not exist currently on the network')

            else:
                print('Invalid option type -h to see options')
            

        elif command[0:11] == 'device scan':
            device_scan()
            '''
        elif command[0:4] == 'ddos':
            destination_ip, destination_port, threads, interrupt, packet_size, message = command[5:].split('/')
            destination_port = int(destination_port)
            threads = int(threads)
            interrupt = int(interrupt)
            packet_size = int(packet_size)
            ddos(destination_ip, destination_port, threads, interrupt, packet_size, message)'''

        elif command[0:len('read')] == 'read':
            ip, adapter = command[5:].split('/')
            read_packets(ip, adapter)

        elif command[0:4] == 'help':
            displayHelp()

        elif command[0:5] == 'clear':
            clear()

        else:
            print('invalid option type help to view commands')


if __name__ == '__main__':
    main()
