import socket

target = input("Enter IP address: ")

ports = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}

print(f"\nScanning {target}...\n")

for port, service in ports.items():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"Port {port} OPEN ({service})")
    
    sock.close()

print("\nScan complete.")