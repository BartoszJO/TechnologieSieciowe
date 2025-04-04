import socket
import requests
from scapy.all import IP, ICMP, sr1

def get_ip_info(ip):
    """
    Pobiera informacje o adresie IP (lokalizacja, operator, itp.)
    korzystając z API ipinfo.io.
    """
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass
    return {}

target = "8.8.8.8"  # Przykładowy serwer; zamień na adres docelowy z innego kontynentu
max_ttl = 30

print(f"Traceroute do {target}")
for ttl in range(1, max_ttl + 1):
    pkt = IP(dst=target, ttl=ttl) / ICMP()
    reply = sr1(pkt, timeout=2, verbose=0)
    if reply is None:
        print(f"{ttl}: Brak odpowiedzi")
        continue

    ip_addr = reply.src

    # Próba uzyskania nazwy domenowej poprzez reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
    except socket.herror:
        hostname = "Nieznany"

    # Pobranie danych geolokalizacyjnych i operatora
    info = get_ip_info(ip_addr)
    country = info.get("country", "Brak danych")
    region = info.get("region", "Brak danych")
    city = info.get("city", "Brak danych")
    org = info.get("org", "Brak danych")

    print(f"{ttl}: {ip_addr} ({hostname})")
    print(f"    Lokalizacja: {city}, {region}, {country}")
    print(f"    Operator: {org}")

    if ip_addr == target:
        print("Osiągnięto cel!")
        break
