import os
from scapy.all import ICMP, IP, sr1, TCP, sr
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Lock utilisé pour synchroniser les impressions dans la console (multithreading).
# Lock used to synchronize console prints (multithreading).
print_lock = Lock()


# Fonction pour effectuer un ping sur un hôte.
# Function to perform a ping on a host.
def ping(host):
    response = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)
    if response is not None:
        return str(host)  # Retourne l'adresse de l'hôte si une réponse est reçue.
        # Returns the host address if a response is received.
    return None  # Sinon, retourne None.
    # Otherwise, returns None.


def ping_sweep(network, netmask):
    live_hosts = []  # Liste des hôtes actifs.
    # List of live hosts.

    # Nombre de threads à utiliser, basé sur le nombre de cœurs CPU disponibles.
    # Number of threads to use, based on available CPU cores.
    num_threads = os.cpu_count()
    hosts = list(ip_network(network + '/' + netmask).hosts())  # Liste des adresses IP dans le réseau.
    # List of IP addresses in the network.
    total_hosts = len(hosts)  # Nombre total d'hôtes dans le réseau.
    # Total number of hosts in the network.

    # Utilisation d'un ThreadPoolExecutor pour exécuter des tâches en parallèle.
    # Using ThreadPoolExecutor to execute tasks in parallel.
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Dictionnaire pour associer les threads à leurs hôtes respectifs.
        # Dictionary to map threads to their respective hosts.
        futures = {executor.submit(ping, host): host for host in hosts}
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]  # Hôte correspondant à ce thread.
            # Host corresponding to this thread.
            result = future.result()  # Résultat du ping.
            # Ping result.
            with print_lock:
                print(f"Scanning: {i}/{total_hosts}", end="\r")  # Affichage du progrès.
                # Display progress.
                if result is not None:  # Si l'hôte est actif.
                    # If the host is live.
                    print(f"\nHost {host} is online.")
                    live_hosts.append(result)  # Ajouter l'hôte actif à la liste.
                    # Add the live host to the list.

    return live_hosts  # Retourne tous les hôtes actifs.
    # Returns all live hosts.


# Fonction pour scanner un port spécifique sur un hôte donné.
# Function to scan a specific port on a given host.
def scan_port(args):
    ip, port = args  # Décompose l'argument en adresse IP et port.
    # Decomposes the argument into IP address and port.
    response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if response is not None and response[TCP].flags == "SA":  # Si le port est ouvert.
        # If the port is open.
        return port
    return None  # Si le port est fermé ou n'a pas répondu.
    # If the port is closed or didn't respond.


# Fonction pour scanner une plage de ports sur un hôte donné.
# Function to scan a range of ports on a given host.
def port_scan(ip, ports):
    open_ports = []  # Liste des ports ouverts.
    # List of open ports.

    num_threads = os.cpu_count()  # Nombre de threads basés sur le CPU.
    # Number of threads based on the CPU.
    total_ports = len(ports)  # Nombre total de ports à scanner.
    # Total number of ports to scan.

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Associe chaque tâche de scan à un port spécifique.
        # Maps each scanning task to a specific port.
        futures = {executor.submit(scan_port, (ip, port)): port for port in ports}
        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]  # Port correspondant à ce thread.
            # Port corresponding to this thread.
            result = future.result()  # Résultat du scan du port.
            # Port scan result.
            with print_lock:
                print(f"Scanning {ip}: {i}/{total_ports}", end="\r")  # Affichage du progrès.
                # Display progress.
                if result is not None:  # Si le port est ouvert.
                    # If the port is open.
                    print(f"\nPort {port} is open on host {ip}")
                    open_ports.append(result)  # Ajouter le port à la liste.
                    # Add the port to the list.

    return open_ports  # Retourne tous les ports ouverts.
    # Returns all open ports.


# Fonction principale pour trouver les hôtes actifs et scanner leurs ports.
# Main function to find live hosts and scan their ports.
def get_live_hosts_and_ports(network, netmask):
    live_hosts = ping_sweep(network, netmask)  # Analyse des hôtes actifs.
    # Scan live hosts.

    host_port_mapping = {}  # Dictionnaire pour mapper les hôtes à leurs ports ouverts.
    # Dictionary to map hosts to their open ports.
    ports = range(1, 1024)  # Plage des ports à scanner.
    # Range of ports to scan.
    for host in live_hosts:
        open_ports = port_scan(host, ports)  # Scan des ports pour chaque hôte actif.
        # Scan ports for each live host.
        host_port_mapping[host] = open_ports

    return host_port_mapping  # Retourne la correspondance hôte-ports ouverts.
    # Returns the host-open ports mapping.


if __name__ == "__main__":
    import sys

    network = sys.argv[1]  # Adresse réseau fournie en argument.
    # Network address provided as an argument.
    netmask = sys.argv[2]  # Masque réseau fourni en argument.
    # Netmask provided as an argument.
    host_port_mapping = get_live_hosts_and_ports(network, netmask)
    for host, open_ports in host_port_mapping.items():
        print(f"\nHost {host} has the following open ports: {open_ports}")
        # Affiche les hôtes et leurs ports ouverts.
        # Displays hosts and their open ports.
