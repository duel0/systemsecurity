from OpenSSL import crypto
import datetime
import os
from getpass import getpass
from key_security import KeySecurityManager

class RootCA:
    def __init__(self):
        self.CERT_FILE = "root_ca.crt"
        self.KEY_SIZE = 4096
        self.VALID_YEARS = 10
        self.key_manager = KeySecurityManager()

    def create_root_ca(self, force=False):
        # Controlla se i file esistono già
        if not force and os.path.exists(self.CERT_FILE) and self.key_manager.key_exists("root_ca"):
            print("Root CA già esistente. Usa force=True per rigenerare.")
            return False

        # Genera chiave privata
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, self.KEY_SIZE)

        # Crea certificato
        cert = crypto.X509()
        
        # Imposta subject
        subject = cert.get_subject()
        subject.CN = "Root CA"
        subject.O = "My PKI"
        subject.C = "IT"

        # Imposta validità
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.VALID_YEARS * 365 * 24 * 60 * 60)
        
        # Imposta altri campi
        cert.set_version(2)  # X509v3
        cert.set_serial_number(1)
        cert.set_issuer(subject)  # self-signed
        cert.set_pubkey(key)

        # Aggiungi estensioni
        extensions = [
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)
        ]
        
        cert.add_extensions(extensions)

        # Firma il certificato
        cert.sign(key, 'sha512')

        # Ottieni la password per proteggere la chiave
        while True:
            password = getpass("Inserisci la password per proteggere la chiave Root CA: ")
            confirm_password = getpass("Conferma la password: ")
            
            if password == confirm_password:
                break
            print("Le password non coincidono. Riprova.")

        # Salva la chiave privata in modo sicuro
        key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        if not self.key_manager.protect_key("root_ca", key_data, password):
            print("Errore durante il salvataggio sicuro della chiave!")
            return False

        # Salva certificato
        with open(self.CERT_FILE, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        print("Root CA creata con successo!")
        return True

    def get_root_key(self):
        """Recupera la chiave privata dal gestore sicuro"""
        password = getpass("Inserisci la password della Root CA: ")
        key_data = self.key_manager.retrieve_key("root_ca", password)
        
        if key_data:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
        return None

    def display_certificate_info(self):
        if not os.path.exists(self.CERT_FILE):
            print("Certificato non trovato!")
            return

        with open(self.CERT_FILE, 'rb') as f:
            cert_data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

        print("\nInformazioni Certificato Root CA:")
        print("-" * 50)
        print(f"Subject: {cert.get_subject().CN}")
        print(f"Issuer: {cert.get_issuer().CN}")
        print(f"Serial Number: {cert.get_serial_number()}")
        print(f"Not Before: {datetime.datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')}")
        print(f"Not After: {datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')}")
        print(f"Has expired: {cert.has_expired()}")
        
        print("\nExtensions:")
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            print(f"{ext.get_short_name().decode('utf-8')}: {ext.__str__()}")

def main():
    root_ca = RootCA()
    
    while True:
        print("\nRoot CA Manager")
        print("1. Crea Root CA")
        print("2. Visualizza informazioni certificato")
        print("3. Ricrea Root CA (forza rigenerazione)")
        print("4. Verifica accesso alla chiave privata")
        print("5. Esci")
        
        scelta = input("\nScegli un'opzione: ")
        
        if scelta == "1":
            root_ca.create_root_ca()
        elif scelta == "2":
            root_ca.display_certificate_info()
        elif scelta == "3":
            root_ca.create_root_ca(force=True)
        elif scelta == "4":
            key = root_ca.get_root_key()
            if key:
                print("Accesso alla chiave privata riuscito!")
            else:
                print("Impossibile accedere alla chiave privata!")
        elif scelta == "5":
            break
        else:
            print("Opzione non valida!")

        input("\nPremi INVIO per continuare...")

    print("Programma terminato.")

if __name__ == "__main__":
    main()