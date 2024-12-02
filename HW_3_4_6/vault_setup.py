import os
import subprocess
import time
import hvac
import json
import psycopg2
from typing import Tuple

class VaultManager:
    def __init__(self):
        self.vault_process = None
        self.root_token = None
        self.client = None
        self.db_credentials = None
        
    def start_vault(self) -> None:
        """Avvia Vault in modalità dev e cattura il root token"""
        # Avvia vault server -dev in background
        self.vault_process = subprocess.Popen(
            ['vault', 'server', '-dev'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Attendi che Vault si avvii e cattura il Root Token
        for line in iter(self.vault_process.stderr.readline, ''):
            if 'Root Token:' in line:
                self.root_token = line.split('Root Token: ')[1].strip()
                break
        print ("Root Token: ", self.root_token)
        # Imposta variabile d'ambiente
        os.environ['VAULT_TOKEN'] = self.root_token
        
        # Attendi che Vault sia pronto
        time.sleep(2)
        
        # Inizializza client hvac
        self.client = hvac.Client(url='http://127.0.0.1:8200', token=self.root_token)

    def setup_vault(self) -> None:
        """Configura Transit e Database engines"""
        # Abilita Transit Engine
        try:
            self.client.sys.enable_secrets_engine(
                backend_type='transit',
                path='transit'
            )
        except hvac.exceptions.InvalidRequest:
            print("Transit engine già abilitato")

        # Crea chiave per documenti
        self.client.secrets.transit.create_key(name='document-key')
        
        # Abilita Database Engine
        try:
            self.client.sys.enable_secrets_engine(
                backend_type='database',
                path='database'
            )
        except hvac.exceptions.InvalidRequest:
            print("Database engine già abilitato")

        # Configura connessione PostgreSQL
        self.client.write(
            path='database/config/docsecure',
            plugin_name='postgresql-database-plugin',
            allowed_roles='app-role',
            connection_url='postgresql://{{username}}:{{password}}@localhost:5432/docsecure?sslmode=disable',
            username='docsecure_app',
            password='your_password_here'  # Sostituisci con password corretta
        )

        # Configura ruolo database
        self.client.write(
            path='database/roles/app-role',
            db_name='docsecure',
            creation_statements="""
                CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' 
                VALID UNTIL '{{expiration}}';
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public 
                TO "{{name}}";
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";
            """,
            default_ttl='1h',
            max_ttl='24h'
        )

    def get_db_credentials(self) -> Tuple[str, str]:
        """Ottiene credenziali temporanee per il database"""
        response = self.client.read('database/creds/app-role')
        if response and 'data' in response:
            self.db_credentials = {
                'username': response['data']['username'],
                'password': response['data']['password']
            }
            return self.db_credentials['username'], self.db_credentials['password']
        return None, None

    def test_db_connection(self) -> bool:
        """Testa la connessione al database con le credenziali temporanee"""
        if not self.db_credentials:
            return False
        
        try:
            conn = psycopg2.connect(
                dbname="docsecure",
                user=self.db_credentials['username'],
                password=self.db_credentials['password'],
                host="localhost",
                sslmode="disable"
            )
            conn.close()
            return True
        except Exception as e:
            print(f"Errore connessione DB: {e}")
            return False

    def cleanup(self):
        """Pulisce le risorse"""
        if self.vault_process:
            self.vault_process.terminate()
            self.vault_process.wait()

def main():
    vault_mgr = VaultManager()
    try:
        print("Avvio Vault...")
        vault_mgr.start_vault()
        print(f"Root Token: {vault_mgr.root_token}")
        
        print("\nConfigurazione Vault...")
        vault_mgr.setup_vault()
        
        print("\nOttenimento credenziali DB...")
        username, password = vault_mgr.get_db_credentials()
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        print("\nTest connessione DB...")
        if vault_mgr.test_db_connection():
            print("Connessione DB riuscita!")
        else:
            print("Errore connessione DB")
            
        # Mantieni Vault in esecuzione
        input("\nPremi Enter per terminare...")
        
    except Exception as e:
        print(f"Errore: {e}")
    finally:
        vault_mgr.cleanup()

if __name__ == "__main__":
    main()