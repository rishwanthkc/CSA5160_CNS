"""
CSA51 - Program 33: Configure Firewalls
Simulates a software packet-filtering firewall with rule management.
"""
from datetime import datetime

class Firewall:
    def __init__(self):
        self.rules = []
        self.log = []
        self.default_action = "DROP"

    def add_rule(self, priority, action, protocol, src_ip, src_port, dst_ip, dst_port):
        rule = {
            'id': len(self.rules) + 1,
            'priority': priority,
            'action': action.upper(),
            'protocol': protocol.upper(),
            'src_ip': src_ip,
            'src_port': str(src_port),
            'dst_ip': dst_ip,
            'dst_port': str(dst_port),
        }
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r['priority'])
        print(f"Rule {rule['id']} added.")

    def delete_rule(self, rule_id):
        before = len(self.rules)
        self.rules = [r for r in self.rules if r['id'] != rule_id]
        print(f"{'Rule deleted.' if len(self.rules) < before else 'Rule not found.'}")

    def match(self, packet, rule):
        def field_match(rule_val, pkt_val):
            return rule_val in ('*', 'ANY', str(pkt_val))
        return (field_match(rule['protocol'], packet['protocol']) and
                field_match(rule['src_ip'], packet['src_ip']) and
                field_match(rule['src_port'], str(packet['src_port'])) and
                field_match(rule['dst_ip'], packet['dst_ip']) and
                field_match(rule['dst_port'], str(packet['dst_port'])))

    def process_packet(self, packet):
        for rule in self.rules:
            if self.match(packet, rule):
                action = rule['action']
                entry = {
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'packet': packet,
                    'action': action,
                    'rule_id': rule['id']
                }
                self.log.append(entry)
                return action, rule['id']
        self.log.append({'time': datetime.now().strftime("%H:%M:%S"),
                         'packet': packet, 'action': self.default_action, 'rule_id': None})
        return self.default_action, None

    def show_rules(self):
        if not self.rules:
            print("No rules configured.")
            return
        print(f"\n{'ID':<5} {'Pri':<5} {'Action':<8} {'Proto':<8} {'Src IP':<16} {'SPort':<8} {'Dst IP':<16} {'DPort'}")
        print("-" * 80)
        for r in self.rules:
            print(f"{r['id']:<5} {r['priority']:<5} {r['action']:<8} {r['protocol']:<8} "
                  f"{r['src_ip']:<16} {r['src_port']:<8} {r['dst_ip']:<16} {r['dst_port']}")

    def show_log(self):
        if not self.log:
            print("No packets logged.")
            return
        print(f"\n{'Time':<10} {'Proto':<8} {'Src':<20} {'Dst':<20} {'Action':<8} {'Rule'}")
        print("-" * 80)
        for e in self.log[-20:]:
            p = e['packet']
            src = f"{p['src_ip']}:{p['src_port']}"
            dst = f"{p['dst_ip']}:{p['dst_port']}"
            rid = str(e['rule_id']) if e['rule_id'] else 'Default'
            print(f"{e['time']:<10} {p['protocol']:<8} {src:<20} {dst:<20} {e['action']:<8} {rid}")

def load_default_rules(fw):
    fw.add_rule(1, 'ALLOW', 'TCP', '*', '*', '*', '80')
    fw.add_rule(2, 'ALLOW', 'TCP', '*', '*', '*', '443')
    fw.add_rule(3, 'ALLOW', 'TCP', '*', '*', '*', '22')
    fw.add_rule(4, 'DROP',  'TCP', '*', '*', '*', '23')   # Telnet
    fw.add_rule(5, 'DROP',  'UDP', '*', '*', '*', '161')  # SNMP
    fw.add_rule(6, 'ALLOW', 'ICMP', '*', '*', '*', '*')
    fw.add_rule(10, 'DROP', 'ANY', '*', '*', '*', '*')     # Default deny
    print("\nDefault rules loaded.")

def main():
    fw = Firewall()
    print("=" * 65)
    print("          SOFTWARE PACKET-FILTERING FIREWALL")
    print("=" * 65)
    load_default_rules(fw)

    while True:
        print("\n--- Firewall Menu ---")
        print("1. Show rules")
        print("2. Add rule")
        print("3. Delete rule")
        print("4. Test packet")
        print("5. Show log")
        print("6. Exit")
        choice = input("Choice: ").strip()

        if choice == '1':
            fw.show_rules()

        elif choice == '2':
            pri  = int(input("Priority (lower = higher priority): "))
            act  = input("Action (ALLOW/DROP/REJECT): ")
            prot = input("Protocol (TCP/UDP/ICMP/ANY): ")
            sip  = input("Source IP (* for any): ")
            sp   = input("Source Port (* for any): ")
            dip  = input("Dest IP (* for any): ")
            dp   = input("Dest Port (* for any): ")
            fw.add_rule(pri, act, prot, sip, sp, dip, dp)

        elif choice == '3':
            fw.show_rules()
            rid = int(input("Enter Rule ID to delete: "))
            fw.delete_rule(rid)

        elif choice == '4':
            print("\nEnter packet details:")
            prot = input("Protocol (TCP/UDP/ICMP): ").upper()
            sip  = input("Source IP: ")
            sp   = int(input("Source Port (0 for ICMP): ") or 0)
            dip  = input("Dest IP: ")
            dp   = int(input("Dest Port: "))
            packet = {'protocol': prot, 'src_ip': sip, 'src_port': sp,
                      'dst_ip': dip, 'dst_port': dp}
            action, rule_id = fw.process_packet(packet)
            print(f"\nPacket: {prot} {sip}:{sp} → {dip}:{dp}")
            print(f"Decision: {action} (Rule: {rule_id if rule_id else 'Default'})")

        elif choice == '5':
            fw.show_log()

        elif choice == '6':
            print("Exiting firewall.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
