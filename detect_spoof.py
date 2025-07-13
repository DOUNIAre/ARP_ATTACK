import time
import os
# the victim always has his previous arp table ( in this c ase every 5 seconds ) to compare it with the current one
# if the current arp table is different from the previous one it means that there is an arp spoofing attack

def get_arp_table():
    arp = os.popen("arp -a").read()
    return arp

prev_arp = get_arp_table()

while True:
    time.sleep(5) 
    current_arp = get_arp_table()
    if current_arp != prev_arp:
        print("Potential ARP Spoofing Detected!")
        print(current_arp)
    prev_arp = current_arp
