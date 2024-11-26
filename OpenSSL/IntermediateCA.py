from OpenSSL import crypto
import datetime
import os
from getpass import getpass
from key_security import KeySecurityManager
from RootCA import RootCA

class IntermediateCA:
    def __init__(self):
        self.CERT_FILE = "intermediate_ca.crt"
        self.KEY_SIZE = 4096
        self.VALID_YEARS = 5
        self.key_manager = KeySecurityManager()
        self.root_ca = RootCA()

    def create_intermediate_ca(self, force=False):
        # Controlla se i file esistono già
        if not force and os.path.exists(self.CERT_FILE) and self.key_manager.key_exists("intermediate_ca"):
            print("Intermediate CA già esistente. Usa force=True per rigenerare.")
            return False

        # Verifica l'esistenza della Root CA
        if not os.path.exists(self.root_ca.CERT_FILE):
            print("Root CA non trovata! Crea prima la Root CA.")
            return False

        # Ottieni la chiave privata della Root CA
        root_key = self.root_ca.get_root_key()
        if not root_key:
            print("Impossibile accedere alla chiave della Root CA!")
            return False

        # Carica il certificato della Root CA
        with open(self.root_ca.CERT_FILE, 'rb') as f:
            root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Genera chiave privata per Intermediate CA
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, self.KEY_SIZE)

        # Crea certificato
        cert = crypto.X509()
        
        # Imposta subject
        subject = cert.get_subject()
        subject.CN = "Intermediate CA"
        subject.O = "My PKI"
        subject.C = "IT"

        # Imposta validità
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.VALID_YEARS * 365 * 24 * 60 * 60)
        
        # Imposta altri campi
        cert.set_version(2)  # X509v3
        cert.set_serial_number(1000)  # Diverso dalla Root CA
        cert.set_issuer(root_cert.get_subject())  # Emesso dalla Root CA
        cert.set_pubkey(key)

        # Aggiungi estensioni
        extensions = [
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=root_cert)
        ]
        
        cert.add_extensions(extensions)

        # Firma il certificato con la Root CA
        cert.sign(root_key, 'sha512')

        # Ottieni la password per proteggere la chiave
        while True:
            password = getpass("Inserisci la password per proteggere la chiave Intermediate CA: ")
            confirm_password = getpass("Conferma la password: ")
            
            if password == confirm_password:
                break
            print("Le password non coincidono. Riprova.")

        # Salva la chiave privata in modo sicuro
        key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        if not self.key_manager.protect_key("intermediate_ca", key_data, password):
            print("Errore durante il salvataggio sicuro della chiave!")
            return False

        # Salva certificato
        with open(self.CERT_FILE, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        print("Intermediate CA creata con successo!")
        return True

    def get_intermediate_key(self):
        """Recupera la chiave privata dal gestore sicuro"""
        password = getpass("Inserisci la password della Intermediate CA: ")
        key_data = self.key_manager.retrieve_key("intermediate_ca", password)
        
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

        print("\nInformazioni Certificato Intermediate CA:")
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

    def verify_certificate_chain(self):
        """Verifica la catena di certificati"""
        if not os.path.exists(self.CERT_FILE) or not os.path.exists(self.root_ca.CERT_FILE):
            print("Certificati mancanti!")
            return False

        try:
            # Crea store per la verifica
            store = crypto.X509Store()
            
            # Carica e aggiungi Root CA allo store
            with open(self.root_ca.CERT_FILE, 'rb') as f:
                root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                store.add_cert(root_cert)

            # Carica certificato Intermediate CA
            with open(self.CERT_FILE, 'rb') as f:
                intermediate_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            # Crea contesto di verifica
            store_ctx = crypto.X509StoreContext(store, intermediate_cert)
            
            # Verifica
            store_ctx.verify_certificate()
            return True
            
        except crypto.X509StoreContextError as e:
            print(f"Errore nella verifica: {str(e)}")
            return False
        except Exception as e:
            print(f"Errore generico: {str(e)}")
            return False

def main():
    intermediate_ca = IntermediateCA()
    
    while True:
        print("\nIntermediate CA Manager")
        print("1. Crea Intermediate CA")
        print("2. Visualizza informazioni certificato")
        print("3. Ricrea Intermediate CA (forza rigenerazione)")
        print("4. Verifica accesso alla chiave privata")
        print("5. Verifica catena di certificati")
        print("6. Esci")
        
        scelta = input("\nScegli un'opzione: ")
        
        if scelta == "1":
            intermediate_ca.create_intermediate_ca()
        elif scelta == "2":
            intermediate_ca.display_certificate_info()
        elif scelta == "3":
            intermediate_ca.create_intermediate_ca(force=True)
        elif scelta == "4":
            key = intermediate_ca.get_intermediate_key()
            if key:
                print("Accesso alla chiave privata riuscito!")
            else:
                print("Impossibile accedere alla chiave privata!")
        elif scelta == "5":
            if intermediate_ca.verify_certificate_chain():
                print("Verifica della catena di certificati completata con successo!")
            else:
                print("Verifica della catena di certificati fallita!")
        elif scelta == "6":
            break
        else:
            print("Opzione non valida!")

        input("\nPremi INVIO per continuare...")

    print("Programma terminato.")

if __name__ == "__main__":
    main()