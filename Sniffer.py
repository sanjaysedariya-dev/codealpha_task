from scapy.all import sniff, IP, TCP, UDP
def packet_callback(packet):
    if packet.haslayer(IP):
        print("\n-----------------------------")
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)
        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Dest Port      :", packet[TCP].dport)
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Dest Port      :", packet[UDP].dport)
print("🔍 Network Sniffer Started...")
sniff(prn=packet_callback, store=False)