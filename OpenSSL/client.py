import os
import datetime
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import PyPDF2
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

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
            with open("intermediate_ca.key", 'rb') as f:
                int_ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

            # Crea certificato
            cert = crypto.X509()
            cert.get_subject().CN = input("Inserisci il tuo nome completo: ")
            cert.get_subject().emailAddress = input("Inserisci la tua email: ")
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
            ])

            # Firma il certificato con la CA intermedia
            cert.sign(int_ca_key, 'sha256')

            # Salva chiave privata
            with open(self.KEY_FILE, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

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

    def sign_pdf(self):
        if not os.path.exists(self.CERT_FILE) or not os.path.exists(self.KEY_FILE):
            print("Certificato client non trovato. Crealo prima.")
            return False

        try:
            # Input file
            pdf_file = input("Inserisci il path del PDF da firmare: ")
            if not os.path.exists(pdf_file):
                print("File non trovato!")
                return False

            # Carica certificato e chiave
            with open(self.CERT_FILE, 'rb') as f:
                cert_data = f.read()
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            
            with open(self.KEY_FILE, 'rb') as f:
                key_data = f.read()
                key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

            # Leggi il PDF originale
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            pdf_writer = PyPDF2.PdfWriter()

            # Copia tutte le pagine
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            # Crea la firma visibile
            signature = BytesIO()
            c = canvas.Canvas(signature, pagesize=letter)
            
            # Imposta le coordinate
            x_start = 350
            y_start = 700
            box_width = 250
            box_height = 100

            # Assicurati che il canvas sia pulito
            c.saveState()
            
            # Crea un rettangolo bianco come sfondo
            c.setFillColorRGB(1, 1, 1)  # Bianco
            c.setStrokeColorRGB(0.1, 0.4, 0.7)  # Blu scuro per il bordo
            c.setLineWidth(2)
            c.rect(x_start, y_start, box_width, box_height, fill=True, stroke=True)

            # Linea decorativa
            c.setStrokeColorRGB(0.1, 0.4, 0.7)
            c.line(x_start + 10, y_start + 80, x_start + box_width - 10, y_start + 80)

            # Imposta il font e il colore per il testo
            c.setFillColorRGB(0, 0, 0)  # Nero puro per il testo
            
            # Titolo
            c.setFont("Helvetica-Bold", 18)
            c.drawString(x_start + 10, y_start + 85, "System Security")
            
            # Informazioni del firmatario
            c.setFont("Helvetica", 14)
            y_offset = 50
            c.drawString(x_start + 10, y_start + y_offset, f"Firmato da: {cert.get_subject().CN}")
            y_offset -= 20
            c.drawString(x_start + 10, y_start + y_offset, f"Email: {cert.get_subject().emailAddress}")
            y_offset -= 20
            c.drawString(x_start + 10, y_start + y_offset, f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")

            c.restoreState()
            c.save()

            # Crea watermark con la firma
            watermark = PyPDF2.PdfReader(signature)
            page = pdf_writer.pages[0]
            
            # Assicurati che il watermark venga applicato sopra il contenuto esistente
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