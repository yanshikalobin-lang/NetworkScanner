import socket
import time
from datetime import datetime
import csv
import ipaddress
import threading
from queue import Queue

#Service Detection Dictionary
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"

}

# HIGH RISK PORTS
HIGH_RISK_PORTS = [21, 23, 445, 3389]

#Hostname Resolution
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# IP VALIDATION (SAFETY LAYER)
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# PORT PARSING (flexible input)
def parse_ports(port_input):
    ports = set()

    for part in port_input.split(","):
        part = part.strip()

        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


# PORT SCANNER FUNCTION
def scan_port(ip, port, results):
    try:
        risk = "Low"

        if port in HIGH_RISK_PORTS:
            risk = "High"

        service = COMMON_SERVICES.get(port, "Unknown")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))

        if result == 0:
            print(f"[+] Port {port} OPEN ({service}) Risk: {risk}")

            results.append({
                "port": port,
                "status": "open",
                "service": service,
                "risk": risk
            })

        else:
            results.append({
                "port": port,
                "status": "closed",
                "service": service,
                "risk": risk
            })

        sock.close()

    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")

#Multi-threading
def worker(queue, ip, results):
    while not queue.empty():
        port = queue.get()
        scan_port(ip,port, results)
        queue.task_done()


#main scanner logic
def run_scan(ip, ports):
    if not validate_ip(ip):
        print("Invalid IP address")
        return
    
    results = []
    queue = Queue()

    for port in ports:
        queue.put(port)

    threads = []

    for _ in range(50): #thread count
        t = threading.Thread(target=worker, args= (queue, ip, results))
        t.start()
        threads.append(t)
    queue.join()

    return results

#CSV Export
def save_results(results, filename="scan_results.csv"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["Timestamp","Port", "Status", "Service", "Risk"])

        for r in results:
            writer.writerow([timestamp,r["port"], r["status"], r["service"], r["risk"]])

    print(f"\n[+] Results saved to {filename}")

#scan timer
def timed_scan(ip, ports):
    start = time.time()

    results = run_scan(ip, ports)

    end = time.time()

    hostname = get_hostname(ip)
    print(f"\nHostname: {hostname}")
    print(f"\nScan completed in {end - start:.2f} seconds")

    return results

#Add CLI test block
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    port_input = input("Enter ports (e.g. 22,80,100-200): ")

    ports = parse_ports(port_input)

    results = timed_scan(target_ip, ports)

    save_results(results)