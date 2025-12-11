# Xscan – TCP Port Scanner in Python
```
  __  __                                    _        ___  
  \ \/ /___  ___ __ _ _ __                 / |      / _ \ 
   \  // __|/ __/ _` | '_ \      _____     | |     | | | |
   /  \\__ \ (_| (_| | | | |    |_____|    | |  _  | |_| |
  /_/\_\___/\___\__,_|_| |_|               |_| (_)  \___/ 
                                                           
```

Xscan is a modular TCP port scanner written in python, designed as a learning project in cybersecurity and network programming.
It performs host-based network reconnaissance by detecting open TCP ports through ```connect()``` scanning, with configurable timeouts and multithreading.

## Table of Contents

- Features

- Installation

- Usage

- Examples

### Features 
##### Scan Modes

- Scan a single port

- Scan multiple specific ports (-p 22 80 443)

- Scan a range of ports (-r 1 1000)

- Scan common ports (22, 80, 443, 8080)

##### Execution Controls

- Verbose mode to display every scanned port

- Custom timeout for connection attempts

- Configurable multithreading (fast scanning)

### Installation

Clone the repository and run the script:

```bash
git clone https://github.com/CyprienThuillier/port-scanner
cd port-scanner
python3 src/scanner.py --help
```

No external dependencies are required.

### Usage

The scanner exposes a full command-line interface:

Basic Usage
```bash
python3 src/scanner.py -t 192.168.1.10 -p 22
```

Scan multiple ports
```bash
python3 src/scanner.py -t 192.168.1.10 -p 22 80 443
```

Scan a port range
```bash
python3 src/scanner.py -t 192.168.1.10 -r 1 1024
```

Scan common ports
```bash
python3 src/scanner.py -t 192.168.1.10 -c
```

Verbose mode
```bash
python3 scanner.py -t 192.168.1.10 -r 1 200 -v
```

Custom timeout
```bash
python3 scanner.py -t 192.168.1.10 -p 22 --timeout 0.5
```

Multithread mode
```bash
python3 scanner.py -t 192.168.1.10 -r 1 500 --threads 200
```

### Examples
Single Port Scan
```bash
PORT            STATE     SERVICE
----------------------------------
[+] 22    tcp    OPEN      ssh
```
Scan Common Ports
```bash
PORT            STATE     SERVICE
----------------------------------
[-] 22    tcp    CLOSED
[-] 80    tcp    CLOSED
[+] 8080  tcp    OPEN      http-alt
```
Verbose Mode Output
```bash
[-] 1     tcp    CLOSED
[-] 2     tcp    CLOSED
[+] 22    tcp    OPEN     ssh
[-] 23    tcp    CLOSED
...
```
As the tool evolves, modules may be split (e.g., utils, validators, scan engines).
