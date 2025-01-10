import sys
import argparse
import socket

# Fonction pour récupérer la bannière d'un service sur un port donné.
# Function to retrieve the banner of a service on a given port.
def get_service_banner(ip, port):
    try:
        # Crée une socket TCP pour se connecter au service.
        # Create a TCP socket to connect to the service.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Définit un délai d'attente de 3 secondes pour la connexion.
        # Sets a timeout of 3 seconds for the connection.
        sock.connect((ip, int(port)))  # Connecte la socket à l'adresse IP et au port.
        # Connects the socket to the IP address and port.

        # Envoie une requête HTTP simple pour tenter de recevoir une réponse.
        # Sends a simple HTTP request to attempt to get a response.
        sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")

        # Lit jusqu'à 1024 octets de la réponse du service.
        # Reads up to 1024 bytes of the service's response.
        banner = sock.recv(1024)

        sock.close()  # Ferme la connexion une fois la réponse reçue.
        # Closes the connection after receiving the response.

        # Retourne la bannière décodée en UTF-8 (en ignorant les erreurs de décodage).
        # Returns the banner decoded in UTF-8 (ignoring decoding errors).
        return banner.decode('utf-8', errors='ignore')
    except Exception:
        # Si une erreur se produit (ex. port fermé), retourne None.
        # If an error occurs (e.g., port closed), return None.
        return None

# Fonction principale pour exécuter le scanner.
# Main function to run the scanner.
def main():
    # Crée un analyseur d'arguments pour accepter les options en ligne de commande.
    # Create an argument parser to accept command-line options.
    parser = argparse.ArgumentParser(description='Service Banner Scanner')

    # Ajoute un argument obligatoire pour spécifier l'adresse IP à scanner.
    # Add a required argument to specify the IP address to scan.
    parser.add_argument('ip', help='IP address to scan')

    # Ajoute une option pour fournir une liste de ports à scanner (séparés par des virgules).
    # Add an option to provide a list of ports to scan (comma-separated).
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (comma-separated)')

    # Analyse les arguments passés en ligne de commande.
    # Parse the arguments passed from the command line.
    args = parser.parse_args()

    ip = args.ip  # Adresse IP spécifiée par l'utilisateur.
    # IP address specified by the user.
    ports = [port.strip() for port in args.ports.split(',')]  # Liste des ports à scanner.
    # List of ports to scan.

    print(f"Scanning IP: {ip}")  # Indique le début du scan pour l'adresse IP spécifiée.
    # Indicates the start of the scan for the specified IP address.
    for port in ports:
        # Scanne chaque port spécifié par l'utilisateur.
        # Scan each port specified by the user.
        print(f"Scanning port {port} on IP {ip}")

        # Tente de récupérer la bannière pour le port en cours.
        # Attempt to retrieve the banner for the current port.
        banner = get_service_banner(ip, port)

        if banner:
            # Si une bannière est trouvée, l'affiche.
            # If a banner is found, display it.
            print(f"Service banner for port {port} on IP {ip}:\n{banner}\n")
        else:
            # Sinon, indique qu'aucune bannière n'a été trouvée.
            # Otherwise, indicate that no banner was found.
            print(f"No service banner found for port {port} on IP {ip}\n")

if __name__ == "__main__":
    main()
