def get_service_banner(ip, port):
    # Essaie de se connecter à un port spécifique sur l'adresse IP donnée et de récupérer la bannière du service.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Crée une socket pour la communication TCP.
        sock.settimeout(3)  # Définit un délai d'expiration pour la tentative de connexion.
        sock.connect((ip, int(port)))  # Se connecte à l'IP et au port spécifiés.
        sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")  # Envoie une requête HTTP pour récupérer la bannière.
        banner = sock.recv(1024)  # Reçoit jusqu'à 1024 octets en réponse.
        sock.close()  # Ferme la connexion après avoir reçu la réponse.
        return banner.decode('utf-8', errors='ignore')  # Décode la bannière en texte lisible, en ignorant les erreurs.
    except Exception:
        return None  # Retourne None si une erreur survient.


def ping(host):
    # Simule un "ping" en envoyant un paquet ICMP et vérifie si l'hôte répond.
    response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)  # Envoie un paquet ICMP et attend une réponse.
    if response is not None:  # Si une réponse est reçue...
        return str(host)  # L'hôte est actif.
    return None  # Aucun retour signifie que l'hôte est inactif.


def port_scan(ip, ports):
    # Scanne les ports d'une adresse IP et identifie les ports ouverts.
    open_ports = []  # Liste pour stocker les ports ouverts.
    for port in ports:  # Parcourt chaque port spécifié.
        response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)  # Envoie un paquet SYN.
        if response is not None and response[TCP].flags == "SA":  # Vérifie si une réponse SYN-ACK est reçue.
            open_ports.append(port)  # Ajoute le port à la liste des ports ouverts.
    return open_ports  # Retourne la liste des ports ouverts.


def scan_host(ip, ports):
    # Scanne un hôte pour collecter des informations sur ses services ouverts.
    nm = nmap.PortScanner()  # Initialise un scanner Nmap.
    nm.scan(ip, ports)  # Lance un scan Nmap sur l'IP et les ports spécifiés.
    host_infos = []  # Liste pour stocker les informations des services.
    for proto in nm[ip].all_protocols():  # Parcourt tous les protocoles détectés (TCP, UDP, etc.).
        for port in nm[ip][proto].keys():  # Parcourt chaque port ouvert pour ce protocole.
            # Ajoute les informations du port au dictionnaire.
            host_infos.append({
                'ip': ip,
                'port': port,
                'name': nm[ip][proto][port]['name'],  # Nom du service.
                'product': nm[ip][proto][port]['product'],  # Produit ou logiciel du service.
                'version': nm[ip][proto][port]['version']  # Version du service.
            })
    return host_infos  # Retourne les informations collectées.


def output_to_csv(output_file, host_info):
    # Sauvegarde les informations d'un hôte dans un fichier CSV.
    fieldnames = ["ip", "port", "name", "product", "version"]  # Noms des colonnes dans le fichier CSV.
    with open(output_file, "a") as f:  # Ouvre le fichier en mode append (ajout).
        writer = csv.DictWriter(f, fieldnames=fieldnames)  # Crée un writer CSV.
        writer.writerow(host_info)  # Écrit les informations de l'hôte dans le fichier.


def main():
    subnet = input("Enter subnet (e.g., 192.168.X.X): ").strip()
    mask = int(input("Enter mask (e.g., 24): ").strip())
    ports = input("Enter ports to scan (comma-separated): ").strip()

    live_hosts = ping_sweep(subnet, mask)
    print("Ping sweep completed.\n")

    for host in live_hosts:
        open_ports = port_scan(host, range(1, 1025))
        print(f"Open ports on host {host}: {open_ports}\n")

        for port in open_ports:
            host_infos = scan_host(host, str(port))
            for host_info in host_infos:
                output_to_csv("scan_results.csv", host_info)
                print("\nScan results:")
                for k, v in host_info.items():
                    print(f"{k}: {v}")
                print()

if __name__ == "__main__":
    main()
