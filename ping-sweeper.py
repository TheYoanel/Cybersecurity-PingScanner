import sys
from scapy.all import ICMP, IP, sr1, ARP, sr
from netaddr import IPNetwork
from concurrent.futures import ThreadPoolExecutor


def arp_request(host):
    """
    Sends an ARP request to a specific host to discover its MAC address./Envoie une requête ARP à un hôte spécifique pour découvrir son adresse MAC.
    """
    arp_req = ARP(pdst=str(host))
    response, _ = sr(arp_req, timeout=1, verbose=0)

    if response:
        for _, rcv in response:
            if hasattr(rcv, 'hwsrc'):
                return rcv.hwsrc  # Return the MAC address found / Retourne l'adresse MAC trouvée
    return None  # No host found or no ARP response / Aucun hôte trouvé ou pas de réponse ARP


def ping_host(host):
    """
    Sends a ping (ICMP) to a host after resolving it via ARP./Envoie un ping (ICMP) à un hôte après résolution via ARP.
    """
    mac_address = arp_request(host)
    if mac_address:
        print(f"ARP: Host {host} found with MAC {mac_address}")
        response = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)
        if response:
            return str(host)  # Host is online / L'hôte est en ligne
    return None  # Host is offline or no response / L'hôte n'est pas en ligne ou aucune réponse


def ping_sweep(network, netmask):
    """
    Performs a ping sweep over a network to find live hosts./Effectue un balayage ping sur un réseau pour trouver les hôtes actifs.
    """
    live_hosts = []
    ip_network = IPNetwork(f"{network}/{netmask}")

    # Test the gateway first / Tester d'abord la passerelle
    gateway = str(ip_network.network + 1)  # Gateway is usually .1 / La passerelle est généralement .1
    print(f"Testing gateway: {gateway}")

    gateway_mac = arp_request(gateway)
    if gateway_mac:
        print(f"ARP: Gateway {gateway} found with MAC {gateway_mac}")
        response = sr1(IP(dst=gateway) / ICMP(), timeout=1, verbose=0)
        if response:
            live_hosts.append(gateway)
            print(f"Gateway {gateway} is online.")
    else:
        print(f"ARP: No response from gateway {gateway}")
        return live_hosts  # Stop if gateway doesn't respond / Arrêter si la passerelle ne répond pas

    # Use ThreadPoolExecutor for parallel host scanning / Utiliser ThreadPoolExecutor pour scanner les hôtes en parallèle
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(ping_host, ip_network.iter_hosts())

    # Add live hosts to the list / Ajouter les hôtes vivants à la liste
    for host in results:
        if host:
            live_hosts.append(host)
            print(f"Host {host} is online.")

    return live_hosts


if __name__ == "__main__":
    """
    Main function to initiate the ping sweep./Fonction principale pour démarrer le balayage ping.
    """
    if len(sys.argv) != 3:
        print("Usage: python ping-sweeper.py <network> <netmask>")
        sys.exit(1)

    network = sys.argv[1]
    netmask = sys.argv[2]

    live_hosts = ping_sweep(network, netmask)
    print("\nCompleted\n")
    print(f"Live hosts: {live_hosts}")
