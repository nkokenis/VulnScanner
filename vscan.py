# External dependencies
import sys
import socket
import argparse
from datetime import datetime

# Function:
# Parse Ports
#
# Description:
# A helper function for input_handler() that parses the ports specified by
# the user during input
def parse_ports(port_input):
    ports = set()
    if '-' in port_input:
        start, end = map(int(port_input.split('-')))
        ports.update(range(start, end + 1))
    elif ',' in port_input:
        ports.update(int(p) for p in port_input.split(','))
    else:
        ports.add(int(port_input))
    return sorted(ports)

# Function:
# Scan Ports
#
# Description:
# A basic port scanner that returns all open ports for a given host
def scan_ports(host, ports, timeout, retries, verbose):
    open_ports = []
    for port in ports:
        try:
            # Initialize a socket stream
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sc:
                sc.settimeout(timeout)
                # Connect to the remote host on the current port
                result = sc.connect_ex((host, port))
                # If we get a response, the port is open
                if result == 0:
                    print(f"[+] Port {port} is open")
                    open_ports.append(port)
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")
    return open_ports

# Function:
# Input Handler
#
# Description:
# This function is responsible for handling user input to the program. The program accepts the following command
# line arguments:
#   [Required] host : Specifies the host to be scanned
#   [Required] -p <port number, list, or range> : Specifies the ports to be scanned on the host
#   [Required] -pA : Scans all ports
#   [Optional] -v : Tell the program to print more verbose output, similar to Nmap
#   [Optional] -h : Prints the help menu, explaining the program and its arguments
#   [Optional] --max-retries <number of retries> : Maximum number of retries to connect to any given host
#   [Optional] --host-timeout <amount of time, in seconds> : Maximum amount of time, in seconds, to try and scan any given host
# *At least one of the arguments -p OR -pA is required
def input_handler():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner")
    
    # Add required positional argument(s)
    parser.add_argument("host", help="Host to be scanned")

    # Create a mutually exclusive argument group for specifying ports to be scanned. At least one of the arguments -p or -pA must be included
    group = parser.add_mutually_exclusive_group(required=True)
    # Custom argument name for -p is ports
    group.add_argument("-p", dest="ports", help="Scan a single port (ex. 22), list of ports (ex. 22,80,443), or range of ports(ex. 1-65535)")
    # Custom argument name for -pA is scan_all_ports
    group.add_argument("-pA", action="store_true", dest="scan_all_ports", help="Scan all ports and all protocols")

    # Add optional arguments
    parser.add_argument("-v", "--verbose", action="store_true", help="Tells the program to print more verbose output, similar to Nmap")
    parser.add_argument("--max-retries", type=int, default=1, help="Maximum number of retries to connect to any given host before giving up. Default = 1")
    parser.add_argument("--max-timeout", type=int, default=20, help="Maximum amount of time, in seconds, to try and scan any given host before giving up. Default = 20 seconds")

    # Parse user input
    args = parser.parse_args()

    # Parse port input
    if args.scan_all_ports:
        ports = list(range(1, 65536))
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print("[-] Invalid port format. Use port number (ex. 22), port list (ex. 22,80,443), or 1-1024")
            exit()
    
    # Scan ports
    try:
        scan_ports(args.host, ports, args.max_timeout)
    except KeyboardInterrupt:
        print(f"[!] Scan cancelled")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("[~] Scan completed")
    return

# Function:
# Main
#
# Description:
# Responsible for coordinating other functions and handling program output
def main():
    input_handler()
    return

if __name__ == "__main__":
    main()