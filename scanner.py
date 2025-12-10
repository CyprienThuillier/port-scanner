import argparse
import socket

# -t / --target
# -p / --port
# -P / --ports (multi ports)
# -r / --range
# -c / --common
# --timeout
# --threads
# -v / --verbose
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

# variables
default_ports = [22, 80, 443, 8080]
args = parser.parse_args()
host = args.target[0]
ports = []
if args.ports:
    ports = args.ports
elif args.range:
    for port in range(args.range[0], args.range[1]+1):
        ports.append(port)

# scan functions
def scan(host, ports):
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            result = s.connect_ex((host, port))
            if result == 0:
                print(f"{GREEN}[+]{RESET} {port}/tcp OPEN")
            else:
                print(f"{RED}[-]{RESET} {port}/tcp CLOSED")
        except Exception as e:
            print(f"{YELLOW}[E]{RESET} Error on port {port}: {e}")
        finally:
            s.close()
            
scan(host,ports)