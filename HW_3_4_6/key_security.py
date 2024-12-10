# key_security.py

import os
import base64
import json
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

class KeySecurityManager:
    def __init__(self, base_dir=None):
        """
        Inizializza il KeySecurityManager
        :param base_dir: Directory base opzionale per le chiavi sicure
        """
        if base_dir:
            self.keys_dir = os.path.join(base_dir, "secure_keys")
        else:
            self.keys_dir = "secure_keys"
        self.config_file = os.path.join(self.keys_dir, "config.json")
        self.initialize_security_directory()

    def initialize_security_directory(self):
        """Inizializza la directory sicura per le chiavi"""
        try:
            if not os.path.exists(self.keys_dir):
                os.makedirs(self.keys_dir, mode=0o700)  # Solo il proprietario può accedere
                # Inizializza il file di configurazione
                config = {
                    "salt": base64.b64encode(os.urandom(16)).decode('utf-8'),
                    "keys": {}
                }
                self._save_config(config)
            
            # Verifica/correggi i permessi anche se la directory esiste già
            os.chmod(self.keys_dir, 0o700)
            if os.path.exists(self.config_file):
                os.chmod(self.config_file, 0o600)
            
            return True
        except Exception as e:
            print(f"Errore nell'inizializzazione della directory sicura: {str(e)}")
            return False

    def _save_config(self, config):
        """Salva la configurazione in modo sicuro"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            os.chmod(self.config_file, 0o600)
            return True
        except Exception as e:
            print(f"Errore nel salvataggio della configurazione: {str(e)}")
            return False

    def _load_config(self):
        """Carica la configurazione"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Errore nel caricamento della configurazione: {str(e)}")
            return None

    def _get_encryption_key(self, password):
        """
        Genera una chiave di cifratura dal password
        :param password: Password da cui derivare la chiave
        :return: Oggetto Fernet per cifratura/decifratura
        """
        config = self._load_config()
        if not config:
            raise ValueError("Configurazione non trovata")
        
        salt = base64.b64decode(config['salt'].encode('utf-8'))
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def protect_key(self, key_type, key_data, password):
        """
        Protegge una chiave privata con cifratura
        :param key_type: Tipo di chiave ('root_ca', 'intermediate_ca', o 'user')
        :param key_data: Dati della chiave da proteggere
        :param password: Password per la protezione
        :return: Boolean che indica il successo dell'operazione
        """
        try:
            if isinstance(key_data, str):
                key_data = key_data.encode()

            # Genera la chiave di cifratura
            fernet = self._get_encryption_key(password)
            
            # Cifra la chiave privata
            encrypted_data = fernet.encrypt(key_data)
            
            # Salva la chiave cifrata
            key_file = os.path.join(self.keys_dir, f"{key_type}.enc")
            with open(key_file, 'wb') as f:
                f.write(encrypted_data)
            os.chmod(key_file, 0o600)

            # Aggiorna il config file
            config = self._load_config()
            if not config:
                return False

            config['keys'][key_type] = {
                'file': os.path.basename(key_file),
                'created': datetime.datetime.now().isoformat(),
                'last_accessed': datetime.datetime.now().isoformat()
            }
            return self._save_config(config)

        except Exception as e:
            print(f"Errore durante la protezione della chiave: {str(e)}")
            return False

    def retrieve_key(self, key_type, password):
        """
        Recupera una chiave privata protetta
        :param key_type: Tipo di chiave da recuperare
        :param password: Password per decifrare la chiave
        :return: Chiave decifrata o None in caso di errore
        """
        try:
            key_file = os.path.join(self.keys_dir, f"{key_type}.enc")
            if not os.path.exists(key_file):
                raise FileNotFoundError(f"Chiave {key_type} non trovata")

            # Leggi la chiave cifrata
            with open(key_file, 'rb') as f:
                encrypted_data = f.read()

            # Decifra la chiave
            fernet = self._get_encryption_key(password)
            decrypted_data = fernet.decrypt(encrypted_data)

            # Aggiorna l'ultimo accesso
            config = self._load_config()
            if config and key_type in config['keys']:
                config['keys'][key_type]['last_accessed'] = datetime.datetime.now().isoformat()
                self._save_config(config)

            return decrypted_data

        except Exception as e:
            print(f"Errore durante il recupero della chiave: {str(e)}")
            return None

    def change_password(self, key_type, old_password, new_password):
        """
        Cambia la password per una chiave specifica
        :param key_type: Tipo di chiave
        :param old_password: Vecchia password
        :param new_password: Nuova password
        :return: Boolean che indica il successo dell'operazione
        """
        try:
            # Recupera la chiave con la vecchia password
            key_data = self.retrieve_key(key_type, old_password)
            if not key_data:
                raise ValueError("Password vecchia non corretta o chiave non trovata")

            # Proteggi la chiave con la nuova password
            return self.protect_key(key_type, key_data, new_password)

        except Exception as e:
            print(f"Errore durante il cambio password: {str(e)}")
            return False

    def list_protected_keys(self):
        """
        Lista tutte le chiavi protette
        :return: Dizionario con le informazioni delle chiavi
        """
        config = self._load_config()
        return config['keys'] if config else {}

    def delete_key(self, key_type):
        """
        Elimina una chiave protetta
        :param key_type: Tipo di chiave da eliminare
        :return: Boolean che indica il successo dell'operazione
        """
        try:
            key_file = os.path.join(self.keys_dir, f"{key_type}.enc")
            if os.path.exists(key_file):
                os.remove(key_file)

            config = self._load_config()
            if config and key_type in config['keys']:
                del config['keys'][key_type]
                return self._save_config(config)
            return True

        except Exception as e:
            print(f"Errore durante l'eliminazione della chiave: {str(e)}")
            return False

    def verify_password(self, key_type, password):
        """
        Verifica se una password è corretta per una determinata chiave
        :param key_type: Tipo di chiave
        :param password: Password da verificare
        :return: Boolean che indica se la password è corretta
        """
        try:
            return self.retrieve_key(key_type, password) is not None
        except Exception:
            return False
    

def print_menu():
    """Stampa il menu principale"""
    print("\n=== Gestore Sicuro delle Chiavi ===")
    print("1. Proteggi una nuova chiave")
    print("2. Recupera una chiave")
    print("3. Lista chiavi protette")
    print("4. Cambia password di una chiave")
    print("5. Verifica password di una chiave")
    print("6. Elimina una chiave")
    print("0. Esci")
    print("================================")

def get_key_type():
    """Richiede all'utente il tipo di chiave"""
    print("\nTipi di chiave disponibili:")
    print("1. Root CA")
    print("2. Intermediate CA")
    print("3. User")
    print("4. Altro (personalizzato)")
    
    choice = input("Seleziona il tipo di chiave (1-4): ")
    if choice == "1":
        return "root_ca"
    elif choice == "2":
        return "intermediate_ca"
    elif choice == "3":
        return "user"
    elif choice == "4":
        return input("Inserisci il nome personalizzato per la chiave: ")
    else:
        return None

def main():
    key_manager = KeySecurityManager()
    
    while True:
        print_menu()
        choice = input("Seleziona un'opzione (0-6): ")
        
        if choice == "0":
            print("\nUscita dal programma...")
            break
            
        elif choice == "1":
            # Proteggi una nuova chiave
            key_type = get_key_type()
            if not key_type:
                print("Tipo di chiave non valido!")
                continue
                
            try:
                file_path = input("\nInserisci il percorso del file della chiave: ")
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                
                password = getpass("Inserisci la password per proteggere la chiave: ")
                confirm_password = getpass("Conferma la password: ")
                
                if password != confirm_password:
                    print("Le password non coincidono!")
                    continue
                
                if key_manager.protect_key(key_type, key_data, password):
                    print(f"\nChiave {key_type} protetta con successo!")
                else:
                    print("\nErrore durante la protezione della chiave")
            
            except FileNotFoundError:
                print("\nFile non trovato!")
            except Exception as e:
                print(f"\nErrore: {str(e)}")
                
        elif choice == "2":
            # Recupera una chiave
            key_type = get_key_type()
            if not key_type:
                print("Tipo di chiave non valido!")
                continue
                
            try:
                password = getpass("Inserisci la password della chiave: ")
                key_data = key_manager.retrieve_key(key_type, password)
                
                if key_data:
                    save_path = input("Inserisci il percorso dove salvare la chiave recuperata: ")
                    with open(save_path, 'wb') as f:
                        f.write(key_data)
                    print(f"\nChiave {key_type} recuperata e salvata con successo in {save_path}")
                else:
                    print("\nImpossibile recuperare la chiave. Password errata o chiave non trovata.")
                    
            except Exception as e:
                print(f"\nErrore: {str(e)}")
                
        elif choice == "3":
            # Lista chiavi protette
            protected_keys = key_manager.list_protected_keys()
            if protected_keys:
                print("\nChiavi protette:")
                for key_type, info in protected_keys.items():
                    print(f"\nTipo: {key_type}")
                    print(f"Creata il: {info['created']}")
                    print(f"Ultimo accesso: {info['last_accessed']}")
            else:
                print("\nNessuna chiave protetta trovata")
                
        elif choice == "4":
            # Cambia password
            key_type = get_key_type()
            if not key_type:
                print("Tipo di chiave non valido!")
                continue
                
            try:
                old_password = getpass("Inserisci la vecchia password: ")
                new_password = getpass("Inserisci la nuova password: ")
                confirm_password = getpass("Conferma la nuova password: ")
                
                if new_password != confirm_password:
                    print("Le password non coincidono!")
                    continue
                
                if key_manager.change_password(key_type, old_password, new_password):
                    print(f"\nPassword della chiave {key_type} cambiata con successo!")
                else:
                    print("\nErrore durante il cambio password")
                    
            except Exception as e:
                print(f"\nErrore: {str(e)}")
                
        elif choice == "5":
            # Verifica password
            key_type = get_key_type()
            if not key_type:
                print("Tipo di chiave non valido!")
                continue
                
            password = getpass("Inserisci la password da verificare: ")
            if key_manager.verify_password(key_type, password):
                print("\nPassword corretta!")
            else:
                print("\nPassword non corretta o chiave non trovata")
                
        elif choice == "6":
            # Elimina chiave
            key_type = get_key_type()
            if not key_type:
                print("Tipo di chiave non valido!")
                continue
                
            confirm = input(f"Sei sicuro di voler eliminare la chiave {key_type}? (s/N): ")
            if confirm.lower() == 's':
                if key_manager.delete_key(key_type):
                    print(f"\nChiave {key_type} eliminata con successo!")
                else:
                    print("\nErrore durante l'eliminazione della chiave")
            else:
                print("\nOperazione annullata")
                
        else:
            print("\nOpzione non valida!")
        
        input("\nPremi INVIO per continuare...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgramma terminato dall'utente")
    except Exception as e:
        print(f"\nErrore imprevisto: {str(e)}")