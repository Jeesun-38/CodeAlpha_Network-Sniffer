# Advanced Network Sniffer

## Description
An advanced Python-based network sniffer that captures and analyzes network traffic. This tool allows you to monitor packets on different ports and stores the captured data in an SQLite database for further analysis.

## Features
- Captures and logs network packets in real-time
- Filters traffic based on protocol or port
- Stores captured packet details in an SQLite database
- Supports multiple protocol options (HTTP, HTTPS, FTP, SSH, DNS, SMTP, POP3)

## Requirements
Before running the sniffer, ensure you have the necessary dependencies installed (For Linux):

```bash
sudo apt update
sudo apt install python3-pip
pip3 install scapy
```

## Usage
Run the script with `sudo` to capture packets on a specific network interface and port:

```bash
sudo python3 advanced_network_sniffer.py -i <interface> -p <port_option>
```

### Example:
```bash
sudo python3 advanced_network_sniffer.py -i eth0 -p 1
```
This will capture HTTP (port 80) traffic on the `eth0` interface.

### Available Port Options:
| Option | Protocol | Port |
|--------|----------|------|
| 1      | HTTP     | 80   |
| 2      | HTTPS    | 443  |
| 3      | FTP      | 21   |
| 4      | SSH      | 22   |
| 5      | DNS      | 53   |
| 6      | SMTP     | 25   |
| 7      | POP3     | 110  |

## Viewing Captured Data
Captured packets are stored in an SQLite database named `network_traffic.db`. You can view the data using the following command:

```bash
sqlite3 network_traffic.db "SELECT * FROM packets;"
```

## Notes
- Run the script with root privileges (`sudo`) as packet sniffing requires elevated permissions.
- Ensure the selected network interface is in promiscuous mode if you want to capture all network traffic.

## License
This project is open-source and available for free use and modification.

## Contribution
Feel free to submit issues or pull requests to improve the project!

