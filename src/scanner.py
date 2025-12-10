import argparse
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

parser = argparse.ArgumentParser()

# arguments
parser.add_argument('-t', '--target', type=str, help='Target IP adress or hostname to scan', required=True)
parser.add_argument('-p', '--ports', nargs='+', type=int, help='Scan specific ports', required=False)
parser.add_argument('-c', '--common', nargs='?', const=True, help='Scan common ports (22, 80, 443, 8080)', required=False)
parser.add_argument('-r', '--range', nargs=2, type=int, help='Scan every port in a range', required=False)
parser.add_argument('-v', '--verbose', action='store_true', help='Show every scans (failed scans too)', required=False)
parser.add_argument('--timeout', type=float, help='Set timeout for socket connections (default: 1 second)', required=False)
parser.add_argument('--threads', type=int, help='Number of threads for scanning', required=False)

args = parser.parse_args()

# variables
ports =[]
common_ports = [22, 80, 443, 8080]
threads = 50

# functions
def scan_port(host, port, timeout):
    opened_ports = 0
    closed_ports = 0
    start_time = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        response = s.connect_ex((host, port))

        if response == 0:
            try:
                service = socket.getservbyport(port)

            except:
                service = ''

            print(f"{GREEN}{'[+]':<4}{RESET}{port:<5}/{'tcp':<6}{'OPEN':<10}{service}")
            opened_ports += 1

        else:
            closed_ports += 1
            if args.verbose:
                print(f"{'[-]':<4}{port:<5}/{'tcp':<6}{'CLOSED':<4}")

    except socket.gaierror:
        print(f"{YELLOW}{'[E]':<4}{RESET}Host name resolution failed")

    except PermissionError:
        print(f"{YELLOW}{'[E]':<4}{RESET}Need sudo for scanning privileged ports (<1024)")

    except Exception as e:
        print(f"{YELLOW}{'[E]':<4}{RESET}Error on port {port}: {e}")

    end_time = time.time()
    delt_time = round((end_time - start_time), 3)
    print(f"Scan completed in {delt_time}s\nOpen ports : {opened_ports}\nClosed ports : {closed_ports}")

def scan_sev_ports(host, ports, timeout):
    opened_ports = 0
    closed_ports = 0
    start_time = time.time()
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            response = s.connect_ex((host, port))

            if response == 0:
                try:
                    service = socket.getservbyport(port)

                except:
                    service = ''

                print(f"{GREEN}{'[+]':<4}{RESET}{port:<5}/{'tcp':<6}{'OPEN':<10}{service}")
                opened_ports += 1

            else:
                closed_ports += 1
                if args.verbose:
                    print(f"{'[-]':<4}{port:<5}/{'tcp':<6}{'CLOSED':<4}")

        except socket.gaierror:
            print(f"{YELLOW}{'[E]':<4}{RESET}Host name resolution failed")

        except PermissionError:
            print(f"{YELLOW}{'[E]':<4}{RESET}Need sudo for scanning privileged ports (<1024)")

        except Exception as e:
            print(f"{YELLOW}{'[E]':<4}{RESET}Error on port {port}: {e}")

    end_time = time.time()
    delt_time = round((end_time - start_time), 3)
    print(f"\nScan completed in {delt_time}s\nOpen ports : {opened_ports}\nClosed ports : {closed_ports}")

def host_checker(host):
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False

def port_checker(port):
    if 0 < port <= 65535:
        return True
    else:
        return False
    
def timeout_checker(timeout):
    if timeout>0:
        return True
    else:
        return False
    
def range_checker(start, end):
    if start > end:
        tmp = start
        start = end
        end = tmp
    return (start, end)

def main():

    # args
    host = args.target
    if args.timeout and timeout_checker(args.timeout):
        timeout = args.timeout
    elif args.timeout:
        print(f"{YELLOW}{'[E]':<4}{RESET}Invalid timeout (expected: t > 0)")
        exit(0)
    else:
        timeout = 1
    
    if host_checker(host):
        if args.ports:
            if len(args.ports) == 1 and port_checker(args.ports[0]):
                print(f"{'PORT':<15} {'STATE':<10}{'SERVICE'}")
                print("-" * 34)
                scan_port(host, args.ports[0], timeout)

            elif len(args.ports) > 1:
                for port in args.ports:
                    if not port_checker(port):
                        print(f"{YELLOW}{'[E]':<4}{RESET}Invalid port {port} (expected: 0 < port < 65535)")
                        exit(0)
                print(f"{'PORT':<15} {'STATE':<10}{'SERVICE'}")
                print("-" * 34)
                scan_sev_ports(host, args.ports, timeout)

        elif args.range:
            range_inter = range_checker(args.range[0], args.range[1])
            ports_range = list(range(range_inter[0], range_inter[1]+1))
            print(f"{'PORT':<15} {'STATE':<10}{'SERVICE'}")
            print("-" * 34)
            scan_sev_ports(host, ports_range, timeout)

        elif args.common:
            print(f"{'PORT':<15} {'STATE':<10}{'SERVICE'}")
            print("-" * 34)
            scan_sev_ports(host, common_ports, timeout)

    else:
        print(f"{YELLOW}{'[E]':<4}{RESET}Incorrect host (expected host type: xxx.xxx.xxx.xxx)")            

# def scan_multiple(target,ports,timeout,threads):
#     with ThreadPoolExecutor(max_workers=threads) as executor:
#         for port in ports:
#             executor.submit(scan, target, port, timeout, args.verbose)
            
# scan(host,ports,timeout)

main()