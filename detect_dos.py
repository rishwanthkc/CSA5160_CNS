"""
CSA51 - Program 37: Detect DoS Attacks
Simulates network traffic monitoring and DoS/DDoS attack detection using
rate limiting, SYN flood detection, and IP-based anomaly detection.
"""
import random
import time
from collections import defaultdict, deque
from datetime import datetime

class DoSDetector:
    def __init__(self):
        self.request_counts = defaultdict(lambda: deque(maxlen=1000))
        self.syn_counts = defaultdict(int)
        self.blocked_ips = set()
        self.alerts = []
        self.total_packets = 0

        # Thresholds
        self.rate_limit = 100       # requests per second per IP
        self.syn_threshold = 50     # SYN packets in window
        self.window_seconds = 1
        self.icmp_threshold = 200   # ICMP per second

    def analyze_packet(self, packet):
        self.total_packets += 1
        src_ip = packet['src_ip']
        now = time.time()

        if src_ip in self.blocked_ips:
            return "BLOCKED", f"IP {src_ip} is blocked"

        # Track request timestamps
        self.request_counts[src_ip].append(now)

        # Clean old entries
        window = [t for t in self.request_counts[src_ip] if now - t < self.window_seconds]
        self.request_counts[src_ip] = deque(window, maxlen=1000)

        rate = len(window)
        alerts = []

        # Rate-based detection
        if rate > self.rate_limit:
            alerts.append(f"RATE LIMIT: {rate} req/s from {src_ip}")

        # SYN flood detection
        if packet.get('flags') == 'SYN' and not packet.get('ack'):
            self.syn_counts[src_ip] += 1
            if self.syn_counts[src_ip] > self.syn_threshold:
                alerts.append(f"SYN FLOOD: {self.syn_counts[src_ip]} SYNs from {src_ip}")

        # ICMP flood
        if packet.get('protocol') == 'ICMP' and rate > self.icmp_threshold:
            alerts.append(f"ICMP FLOOD from {src_ip}")

        if alerts:
            for a in alerts:
                self.alerts.append({'time': datetime.now().strftime("%H:%M:%S"),
                                    'alert': a, 'ip': src_ip})
            if rate > self.rate_limit * 2:
                self.blocked_ips.add(src_ip)
                return "BLOCKED", f"Auto-blocked {src_ip} | " + " | ".join(alerts)
            return "ALERT", " | ".join(alerts)

        return "ALLOW", f"Normal traffic from {src_ip} ({rate} req/s)"

    def show_stats(self):
        print(f"\n--- DoS Detection Statistics ---")
        print(f"Total packets analyzed : {self.total_packets}")
        print(f"Blocked IPs            : {len(self.blocked_ips)}")
        print(f"Total alerts           : {len(self.alerts)}")
        if self.blocked_ips:
            print(f"Blocked IP list        : {', '.join(self.blocked_ips)}")
        if self.alerts:
            print(f"\nRecent Alerts:")
            for a in self.alerts[-10:]:
                print(f"  [{a['time']}] {a['alert']}")

def generate_normal_traffic(n=20):
    ips = [f"192.168.1.{i}" for i in range(1, 11)]
    packets = []
    for _ in range(n):
        packets.append({
            'src_ip': random.choice(ips),
            'dst_ip': '10.0.0.1',
            'protocol': random.choice(['TCP','UDP','ICMP']),
            'flags': random.choice(['SYN', 'ACK', 'DATA', '']),
            'ack': random.choice([True, False]),
            'port': random.choice([80, 443, 22, 53])
        })
    return packets

def generate_dos_traffic(attacker_ip, attack_type, n=200):
    packets = []
    for _ in range(n):
        if attack_type == 'syn_flood':
            packets.append({'src_ip': attacker_ip, 'dst_ip': '10.0.0.1',
                            'protocol': 'TCP', 'flags': 'SYN', 'ack': False, 'port': 80})
        elif attack_type == 'icmp_flood':
            packets.append({'src_ip': attacker_ip, 'dst_ip': '10.0.0.1',
                            'protocol': 'ICMP', 'flags': '', 'ack': False, 'port': 0})
        elif attack_type == 'http_flood':
            packets.append({'src_ip': attacker_ip, 'dst_ip': '10.0.0.1',
                            'protocol': 'TCP', 'flags': 'ACK', 'ack': True, 'port': 80})
    return packets

def main():
    print("=" * 65)
    print("            DoS ATTACK DETECTION SYSTEM")
    print("=" * 65)
    detector = DoSDetector()

    print("\n1. Interactive manual packet entry")
    print("2. Simulate normal + DoS traffic")
    print("3. Simulate specific attack type")
    choice = input("Choice: ").strip()

    if choice == '1':
        print("\nEnter packet details (type 'stats' to see statistics, 'quit' to exit):")
        while True:
            src = input("Source IP (or 'stats'/'quit'): ").strip()
            if src.lower() == 'quit':
                break
            if src.lower() == 'stats':
                detector.show_stats()
                continue
            proto = input("Protocol (TCP/UDP/ICMP): ").strip().upper()
            flags = input("Flags (SYN/ACK/DATA/empty): ").strip().upper()
            ack = 'ACK' in flags
            packet = {'src_ip': src, 'dst_ip': '10.0.0.1', 'protocol': proto,
                      'flags': flags, 'ack': ack, 'port': 80}
            decision, reason = detector.analyze_packet(packet)
            print(f"  → {decision}: {reason}")

    elif choice == '2':
        print("\nSimulating 20 normal packets...")
        normal = generate_normal_traffic(20)
        for p in normal:
            d, r = detector.analyze_packet(p)
            if d != 'ALLOW':
                print(f"  {d}: {r}")
        print("Normal traffic done.")

        attacker = "10.10.10.99"
        print(f"\nSimulating SYN flood from {attacker}...")
        dos = generate_dos_traffic(attacker, 'syn_flood', 100)
        for p in dos:
            d, r = detector.analyze_packet(p)
            if d in ('ALERT', 'BLOCKED'):
                print(f"  {d}: {r}")
                if d == 'BLOCKED':
                    break
        detector.show_stats()

    elif choice == '3':
        attacker = input("Enter attacker IP: ").strip()
        print("Attack types: 1=SYN Flood, 2=ICMP Flood, 3=HTTP Flood")
        at = input("Choose attack type: ").strip()
        types = {'1': 'syn_flood', '2': 'icmp_flood', '3': 'http_flood'}
        atype = types.get(at, 'syn_flood')
        packets = generate_dos_traffic(attacker, atype, 150)
        blocked = False
        for i, p in enumerate(packets):
            d, r = detector.analyze_packet(p)
            if d in ('ALERT', 'BLOCKED'):
                print(f"  Packet {i+1}: {d}: {r}")
                if d == 'BLOCKED':
                    blocked = True
                    break
        if not blocked:
            print("Attack not detected with current thresholds.")
        detector.show_stats()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
