import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

# --threads 
# --udp
# --banner

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

parser = argparse.ArgumentParser()

# arguments
parser.add_argument('-t', '--target', nargs=1, type=str, help='Target IP adress or hostname to scan', required=True)
parser.add_argument('-p', '--ports', nargs='+', type=int, help='Scan specific ports', required=False)
parser.add_argument('-c', '--common', nargs='?', const=True, help='Scan common ports (22, 80, 443, 8080)', required=False)
parser.add_argument('-r', '--range', nargs=2, type=int, help='Scan every port in a range', required=False)
parser.add_argument('-v', '--verbose', action='store_true', help='Show every scans (failed scans too)', required=False)
parser.add_argument('--timeout', type=float, nargs=1, help='Set timeout for socket connections (default: 1 second)', required=False)
parser.add_argument('--threads', type=int, help='Number of threads for scanning', required=False)

# variables
ports = []
common_ports = [22, 80, 443, 8080]
protocol = 'tcp'
threads = 50

# args
args = parser.parse_args()
host = args.target[0]
timeout = 1 if not args.timeout else args.timeout[0]

if args.ports:
    ports = args.ports
elif args.range:
    for port in range(args.range[0], args.range[1]+1):
        ports.append(port)
elif args.common:
    ports = common_ports
if args.threads:
    threads = args.threads

# scan functions
def scan(host, ports, timeout, protocol):
    print(f"PORTS              STATE")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            result = s.connect_ex((host, port))
            if result == 0:
                if len(ports)>1 and args.verbose:
                    print(f"{GREEN}[+]{RESET} {port:<8}/{protocol:<5} OPEN")
                else:
                    print(f"[+] {port:<8}/{protocol:<5} OPEN")
            else:
                if len(ports)>1 and args.verbose:
                    print(f"[-] {port:<8}/{protocol:<5} CLOSED")

        except socket.gaierror:
            print(f"{YELLOW}[E]{RESET} Host name resolution failed")

        except PermissionError:
            print(f"{YELLOW}[E]{RESET} Need sudo for scanning privileged ports (<1024)")

        except Exception as e:
            print(f"{YELLOW}[E]{RESET} Error on port {port}: {e}")

        finally:
            s.close()

def scan_multiple(target,ports,timeout,threads):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for port in ports:
            executor.submit(scan, target, port, timeout, args.verbose)
            
scan(host,ports,timeout,protocol)