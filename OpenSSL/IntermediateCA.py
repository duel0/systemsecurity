from OpenSSL import crypto
import datetime
import os

class IntermediateCA:
    def __init__(self):
        self.KEY_FILE = "intermediate_ca.key"
        self.CERT_FILE = "intermediate_ca.crt"
        self.CSR_FILE = "intermediate_ca.csr"
        self.ROOT_CA_CERT = "root_ca.crt"
        self.ROOT_CA_KEY = "root_ca.key"
        self.KEY_SIZE = 4096
        self.VALID_YEARS = 5

    def create_intermediate_ca(self, force=False):
        # Verifica esistenza Root CA
        if not os.path.exists(self.ROOT_CA_CERT) or not os.path.exists(self.ROOT_CA_KEY):
            print("Root CA non trovata! Crea prima la Root CA.")
            return False

        # Controlla se i file esistono già
        if not force and os.path.exists(self.KEY_FILE) and os.path.exists(self.CERT_FILE):
            print("Intermediate CA già esistente. Usa force=True per rigenerare.")
            return False

        try:
            # Genera chiave privata per Intermediate CA
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, self.KEY_SIZE)

            # Crea CSR (Certificate Signing Request)
            req = crypto.X509Req()
            subject = req.get_subject()
            subject.CN = "Intermediate CA"
            subject.O = "My PKI"
            subject.C = "IT"

            req.set_pubkey(key)
            req.sign(key, 'sha512')

            # Carica Root CA
            with open(self.ROOT_CA_CERT, 'rb') as f:
                root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            with open(self.ROOT_CA_KEY, 'rb') as f:
                root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

            # Crea certificato per Intermediate CA
            cert = crypto.X509()
            cert.set_version(2)
            cert.set_serial_number(2)  # Differente dalla Root CA
            
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(self.VALID_YEARS * 365 * 24 * 60 * 60)
            
            cert.set_issuer(root_cert.get_subject())  # Issuer è la Root CA
            cert.set_subject(req.get_subject())
            cert.set_pubkey(req.get_pubkey())

            # Aggiungi estensioni
            extensions = [
                crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
                crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
                crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=root_cert)
            ]
            
            cert.add_extensions(extensions)

            # Firma con la Root CA
            cert.sign(root_key, 'sha512')

            # Salva chiave privata
            with open(self.KEY_FILE, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

            # Salva CSR (opzionale, ma utile per debug)
            with open(self.CSR_FILE, "wb") as f:
                f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

            # Salva certificato
            with open(self.CERT_FILE, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

            print("Intermediate CA creata con successo!")
            return True

        except Exception as e:
            print(f"Errore durante la creazione dell'Intermediate CA: {str(e)}")
            return False

    def verify_chain(self):
        try:
            # Carica certificati
            with open(self.CERT_FILE, 'rb') as f:
                int_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            with open(self.ROOT_CA_CERT, 'rb') as f:
                root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            # Crea store per la verifica
            store = crypto.X509Store()
            store.add_cert(root_cert)
            
            # Crea contesto di verifica
            store_ctx = crypto.X509StoreContext(store, int_cert)
            
            # Verifica la catena
            store_ctx.verify_certificate()
            
            print("\n=== CATENA DEI CERTIFICATI ===")
            print("\n[Certificato 1 - Intermediate CA]")
            print(f"Subject: {int_cert.get_subject().CN}")
            print(f"Issuer: {int_cert.get_issuer().CN}")
            print(f"Serial: {int_cert.get_serial_number()}")
            print(f"Validità: {datetime.datetime.strptime(int_cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')} -> "
                f"{datetime.datetime.strptime(int_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')}")
            
            print("\n[Certificato 2 - Root CA]")
            print(f"Subject: {root_cert.get_subject().CN}")
            print(f"Issuer: {root_cert.get_issuer().CN}")
            print(f"Serial: {root_cert.get_serial_number()}")
            print(f"Validità: {datetime.datetime.strptime(root_cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')} -> "
                f"{datetime.datetime.strptime(root_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')}")
            
            print("\nVerifica della catena completata con successo!")
            
            # Verifica relazioni
            print("\n=== VERIFICA RELAZIONI ===")
            print(f"Intermediate CA emesso da: {int_cert.get_issuer().CN}")
            print(f"Root CA è self-signed: {root_cert.get_issuer().CN == root_cert.get_subject().CN}")
            
            return True
                
        except Exception as e:
            print(f"Errore nella verifica della catena: {str(e)}")
            return False

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

if __name__ == "__main__":
    int_ca = IntermediateCA()
    
    while True:
        print("\nIntermediate CA Manager")
        print("1. Crea Intermediate CA")
        print("2. Visualizza informazioni certificato")
        print("3. Verifica catena certificati")
        print("4. Ricrea Intermediate CA (forza rigenerazione)")
        print("5. Esci")
        
        scelta = input("\nScegli un'opzione: ")
        
        if scelta == "1":
            int_ca.create_intermediate_ca()
        elif scelta == "2":
            int_ca.display_certificate_info()
        elif scelta == "3":
            int_ca.verify_chain()
        elif scelta == "4":
            int_ca.create_intermediate_ca(force=True)
        elif scelta == "5":
            break
        else:
            print("Opzione non valida!")

    print("Programma terminato.")