from scapy.all import sniff

def packet_callback(packet):
    # Wyświetlenie skróconego opisu pakietu
    print(packet.summary())

# Przechwycenie 10 pakietów na interfejsie "wlp1s0"

sniff(iface="wlp1s0", count=10, prn=packet_callback)
