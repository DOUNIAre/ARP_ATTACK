from scapy.all import ARP, send
import argparse

#the attacker uses this to avoid being detected after the attack
# by restoring the ARP tables of the victim and the gateway
def restore(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(
        op=2,               # arp reply =2 / arp request = 1
        pdst=target_ip,     # Target IP
        hwdst=target_mac,   # Target MAC
        psrc=source_ip,     # Real IP
        hwsrc=source_mac    # Real MAC
    )
    send(packet, count=5, verbose=False)

def main():
    # we use this on cmd (for arguments)
    parser = argparse.ArgumentParser(description="Restore ARP tables of victim and gateway.")
    parser.add_argument("victim_ip", help="IP address of the victim")
    parser.add_argument("victim_mac", help="MAC address of the victim")
    parser.add_argument("gateway_ip", help="IP address of the gateway (router)")
    parser.add_argument("gateway_mac", help="MAC address of the gateway")

    args = parser.parse_args()

    restore(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac)
    restore(args.gateway_ip, args.gateway_mac, args.victim_ip, args.victim_mac)

if __name__ == "__main__":
    main()
