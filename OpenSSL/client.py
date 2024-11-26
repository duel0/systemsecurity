import os
import datetime
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import PyPDF2
from getpass import getpass
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from IntermediateCA import IntermediateCA
from key_security import KeySecurityManager


class Client:
    def __init__(self):
        self.KEY_SIZE = 2048
        self.VALID_YEARS = 1
        
        # File paths
        self.ROOT_CA_CERT = "root_ca.crt"
        self.INT_CA_CERT = "intermediate_ca.crt"
        self.KEY_FILE = "client.key"
        self.CERT_FILE = "client.crt"
        self.P12_FILE = "client.p12"
        self.intermediate_ca = IntermediateCA()
        self.key_manager = KeySecurityManager()

    def create_client_certificate(self, force=False):
        if not force and os.path.exists(self.KEY_FILE) and os.path.exists(self.CERT_FILE):
            print("Certificato client già esistente.")
            return False

        try:
            # Genera coppia di chiavi
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, self.KEY_SIZE)

            # Carica Intermediate CA
            with open(self.INT_CA_CERT, 'rb') as f:
                int_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            
            int_ca_key = self.intermediate_ca.get_intermediate_key()
            # Crea certificato
            cert = crypto.X509()
            cert.get_subject().CN = input("Inserisci il tuo nome completo: ")
            cert.get_subject().emailAddress = input("Inserisci la tua email: ")
            
            # Gestione del ruolo
            while True:
                ruolo = input("Inserisci il tuo ruolo (Docente/Studente): ").capitalize()
                if ruolo in ["Docente", "Studente"]:
                    cert.get_subject().title = ruolo
                    break
                print("Ruolo non valido. Inserisci 'Docente' o 'Studente'.")
            
            cert.get_subject().O = "Università degli Studi di Napoli Federico II"
            cert.get_subject().C = "IT"
            
            cert.set_serial_number(int.from_bytes(os.urandom(16), byteorder='big') & 0xFFFFFFFF)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365*24*60*60*self.VALID_YEARS)
            cert.set_issuer(int_ca_cert.get_subject())
            cert.set_pubkey(key)
            
            # Aggiungi estensioni
            cert.add_extensions([
                crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
                crypto.X509Extension(b"keyUsage", True, b"digitalSignature, nonRepudiation, keyEncipherment"),
                crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth, emailProtection"),
                # Aggiungiamo un'estensione custom per il ruolo in modo corretto
                crypto.X509Extension(b"nsComment", False, ruolo.encode())
            ])

            # Firma il certificato con la CA intermedia
            cert.sign(int_ca_key, 'sha256')

            # Ottieni la password per proteggere la chiave
            while True:
                password = getpass("Inserisci la password per proteggere la chiave del certificato: ")
                confirm_password = getpass("Conferma la password: ")
                
                if password == confirm_password:
                    break
                print("Le password non coincidono. Riprova.")

            # Salva la chiave privata in modo sicuro
            key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
            if not self.key_manager.protect_key("client_cert", key_data, password):
                print("Errore durante il salvataggio sicuro della chiave!")
                return False

            # Salva certificato
            with open(self.CERT_FILE, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

            print("Certificato client creato con successo!")
            return True

        except Exception as e:
            print(f"Errore nella creazione del certificato: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
        

    def get_client_key(self):
        """Recupera la chiave privata dal gestore sicuro"""
        password = getpass("Inserisci la password del Client: ")
        key_data = self.key_manager.retrieve_key("client_cert", password)
        
        if key_data:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
        return None

    def sign_pdf(self):
        if not os.path.exists(self.CERT_FILE):
            print("Certificato client non trovato. Crealo prima.")
            return False

        try:
            # Carica certificato e verifica il ruolo
            with open(self.CERT_FILE, 'rb') as f:
                cert_data = f.read()
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            
            # Verifica il ruolo dal certificato
            role = cert.get_subject().title
            if role != "Docente":
                print("Solo i docenti possono firmare i documenti.")
                return False
            
            # Input file
            pdf_file = input("Inserisci il path del PDF da firmare: ")
            if not os.path.exists(pdf_file):
                print("File non trovato!")
                return False

            key = self.get_client_key()

            # Leggi il PDF originale
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            pdf_writer = PyPDF2.PdfWriter()

            # Copia tutte le pagine
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            signature = BytesIO()
            c = canvas.Canvas(signature, pagesize=letter)

            # Dimensioni del riquadro
            box_width = 250
            box_height = 100

            # Posizione del riquadro in basso a destra
            x_start = 612 - box_width - 20  # Margine destro
            y_start = 20  # Margine inferiore

            # Creare il rettangolo bianco con sfondo opaco
            c.saveState()
            c.setFillColorRGB(1, 1, 1)  # Colore bianco per sfondo
            c.setStrokeColorRGB(0.1, 0.4, 0.7)  # Blu scuro per bordo
            c.setLineWidth(2)
            c.rect(x_start, y_start, box_width, box_height, fill=True, stroke=True)  # Riempire con bianco

            # Linea decorativa
            c.setStrokeColorRGB(0.1, 0.4, 0.7)  # Blu
            c.line(x_start + 10, y_start + box_height - 20, x_start + box_width - 10, y_start + box_height - 20)

            # Impostare il colore del testo
            c.setFillColorRGB(0, 0, 0)  # Nero

            # Aggiungere il testo sopra il rettangolo
            c.setFont("Helvetica-Bold", 12)
            c.drawString(x_start + 10, y_start + box_height - 15, "System Security")

            # Ottenere i dati del firmatario dal certificato
            firmatario = cert.get_subject().CN
            email = cert.get_subject().emailAddress

            c.setFont("Helvetica", 10)
            y_offset = box_height - 40
            c.drawString(x_start + 10, y_start + y_offset, f"Firmato da: {firmatario}")
            y_offset -= 15
            c.drawString(x_start + 10, y_start + y_offset, f"Email: {email}")
            y_offset -= 15
            c.drawString(x_start + 10, y_start + y_offset, f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")

            c.restoreState()
            c.save()

            # Creare il watermark con la firma
            signature.seek(0)
            watermark = PyPDF2.PdfReader(signature)
            page = pdf_writer.pages[0]

            # Applicare il watermark sopra il contenuto esistente
            page.merge_page(watermark.pages[0])

            # Salva il PDF firmato
            output_file = pdf_file.replace('.pdf', '_signed.pdf')
            with open(output_file, 'wb') as f:
                pdf_writer.write(f)

            # Firma i bytes del PDF
            with open(output_file, 'rb') as f:
                pdf_bytes = f.read()
            signature = crypto.sign(key, pdf_bytes, 'sha256')

            # Salva la firma in un file separato
            sig_file = output_file + '.sig'
            with open(sig_file, 'wb') as f:
                f.write(signature)

            print(f"\nPDF firmato salvato come: {output_file}")
            print(f"Firma salvata come: {sig_file}")
            return True

        except Exception as e:
            print(f"Errore durante la firma: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def verify_pdf(self):
        try:
            # Input files
            pdf_file = input("Inserisci il path del PDF da verificare: ")
            sig_file = pdf_file + '.sig'
            
            if not os.path.exists(pdf_file) or not os.path.exists(sig_file):
                print("File PDF o firma non trovati!")
                return False

            # Carica tutti i certificati della catena
            with open(self.CERT_FILE, 'rb') as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            
            with open(self.INT_CA_CERT, 'rb') as f:
                int_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                
            with open(self.ROOT_CA_CERT, 'rb') as f:
                root_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            # Leggi PDF e firma
            with open(pdf_file, 'rb') as f:
                pdf_bytes = f.read()
            
            with open(sig_file, 'rb') as f:
                signature = f.read()

            try:
                # Verifica la firma
                crypto.verify(cert, signature, pdf_bytes, 'sha256')
                
                print("\n=== Verifica della firma ===")
                print("✓ Firma digitale valida!")
                
                print("\n=== Dettagli del firmatario ===")
                print(f"Nome: {cert.get_subject().CN}")
                print(f"Email: {cert.get_subject().emailAddress}")
                print(f"Organizzazione: {cert.get_subject().O}")
                
                print("\n=== Catena dei certificati ===")
                print("1. Certificato client:")
                print(f"   - Soggetto: {cert.get_subject().CN}")
                print(f"   - Emesso da: {cert.get_issuer().CN}")
                print(f"   - Valido dal: {datetime.datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y')}")
                print(f"   - Valido fino al: {datetime.datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y')}")
                
                print("\n2. CA Intermedia:")
                print(f"   - Nome: {int_ca_cert.get_subject().CN}")
                print(f"   - Emesso da: {int_ca_cert.get_issuer().CN}")
                print(f"   - Valido dal: {datetime.datetime.strptime(int_ca_cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y')}")
                print(f"   - Valido fino al: {datetime.datetime.strptime(int_ca_cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y')}")
                
                print("\n3. Root CA:")
                print(f"   - Nome: {root_ca_cert.get_subject().CN}")
                print(f"   - Self-signed: {root_ca_cert.get_subject().CN == root_ca_cert.get_issuer().CN}")
                print(f"   - Valido dal: {datetime.datetime.strptime(root_ca_cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y')}")
                print(f"   - Valido fino al: {datetime.datetime.strptime(root_ca_cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y')}")
                
                return True
            
            except crypto.Error:
                print("\n❌ Firma non valida!")
                return False

        except Exception as e:
            print(f"Errore durante la verifica: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
        
# [Tutto il codice precedente della classe Client rimane invariato]

def print_menu():
    print("\n=== PDF Signer ===")
    print("1. Crea certificato client")
    print("2. Firma PDF")
    print("3. Verifica PDF")
    print("4. Rigenera certificato client")
    print("0. Esci")
    print("================")

def main():
    client = Client()
    
    while True:
        print_menu()
        
        try:
            scelta = input("\nSeleziona un'opzione: ")
            
            if scelta == "1":
                client.create_client_certificate()
            
            elif scelta == "2":
                client.sign_pdf()
            
            elif scelta == "3":
                client.verify_pdf()
            
            elif scelta == "4":
                conferma = input("Sei sicuro di voler rigenerare il certificato? (s/N): ")
                if conferma.lower() == 's':
                    client.create_client_certificate(force=True)
                else:
                    print("Operazione annullata.")
            
            elif scelta == "0":
                print("\nGrazie per aver usato PDF Signer!")
                break
            
            else:
                print("\nOpzione non valida. Riprova.")
            
            input("\nPremi INVIO per continuare...")
            
        except KeyboardInterrupt:
            print("\n\nUscita forzata...")
            break
        except Exception as e:
            print(f"\nErrore imprevisto: {str(e)}")
            input("\nPremi INVIO per continuare...")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nErrore critico: {str(e)}")
        import traceback
        traceback.print_exc()