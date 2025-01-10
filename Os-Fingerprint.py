import sys
import argparse
import socket

def get_service_banner(ip, port):
    try:
        # Crée une socket TCP pour établir une connexion avec le service.
        # Creates a TCP socket to establish a connection with the service.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Définit un délai d'attente de 3 secondes pour la connexion.
        # Sets a 3-second timeout for the connection.
        sock.settimeout(3)

        # Connecte la socket à l'adresse IP et au port spécifiés.
        # Connects the socket to the specified IP address and port.
        sock.connect((ip, int(port)))

        # Envoie une requête HTTP de base pour obtenir une réponse.
        # Sends a basic HTTP request to get a response.
        sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")

        # Récupère jusqu'à 1024 octets de la réponse du service.
        # Retrieves up to 1024 bytes of the service's response.
        banner = sock.recv(1024)

        # Ferme la connexion.
        # Closes the connection.
        sock.close()

        # Retourne la bannière en tant que chaîne UTF-8, en ignorant les erreurs de décodage.
        # Returns the banner as a UTF-8 string, ignoring decoding errors.
        return banner.decode('utf-8', errors='ignore')
    except Exception:
        # Retourne None si une erreur survient (ex. port fermé, timeout).
        # Returns None if an error occurs (e.g., port closed, timeout).
        return None

# Fonction principale qui gère les arguments et exécute le scanner.
# Main function that handles arguments and runs the scanner.
def main():
    # Crée un analyseur d'arguments pour la ligne de commande.
    # Creates an argument parser for the command line.
    parser = argparse.ArgumentParser(description='Service Banner Scanner')

    # Ajoute un argument obligatoire pour spécifier l'adresse IP à scanner.
    # Adds a required argument to specify the IP address to scan.
    parser.add_argument('ip', help='IP address to scan')

    # Ajoute une option pour spécifier les ports à scanner (séparés par des virgules).
    # Adds an option to specify the ports to scan (comma-separated).
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (comma-separated)')

    # Analyse les arguments passés par l'utilisateur.
    # Parses the arguments provided by the user.
    args = parser.parse_args()

    # Récupère l'adresse IP et les ports à partir des arguments.
    # Retrieves the IP address and ports from the arguments.
    ip = args.ip
    ports = [port.strip() for port in args.ports.split(',')]

    print(f"Scanning IP: {ip}")  # Affiche l'adresse IP en cours de scan.
    # Displays the IP address being scanned.
    for port in ports:
        # Parcourt chaque port fourni par l'utilisateur.
        # Iterates over each port provided by the user.
        print(f"Scanning port {port} on IP {ip}")  # Indique le port scanné.
        # Displays the port being scanned.

        # Appelle la fonction pour récupérer la bannière du port.
        # Calls the function to retrieve the banner for the port.
        banner = get_service_banner(ip, port)

        if banner:
            # Si une bannière est trouvée, l'affiche.
            # If a banner is found, it is displayed.
            print(f"Service banner for port {port} on IP {ip}:\n{banner}\n")
        else:
            # Sinon, indique qu'aucune bannière n'a été trouvée.
            # Otherwise, indicates that no banner was found.
            print(f"No service banner found for port {port} on IP {ip}\n")


if __name__ == "__main__":
    main()
