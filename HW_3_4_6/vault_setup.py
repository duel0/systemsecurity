import os
import base64
import json
import datetime
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class VaultTokenManager:
    def __init__(self, base_dir=None):
        """
        Initialize the VaultTokenManager
        :param base_dir: Optional base directory for storing secure vault credentials
        """
        if base_dir:
            self.vault_dir = os.path.join(base_dir, "secure_vault")
        else:
            self.vault_dir = "secure_vault"
        
        self.config_file = os.path.join(self.vault_dir, "config.json")
        self.vault_env_file = os.path.join(self.vault_dir, ".vault_env")
        self.initialize_security_directory()

    def initialize_security_directory(self):
        """Initialize the secure directory for vault credentials"""
        try:
            if not os.path.exists(self.vault_dir):
                os.makedirs(self.vault_dir, mode=0o700)  # Only owner can access
                
                # Initialize the configuration file
                config = {
                    "salt": base64.b64encode(os.urandom(16)).decode('utf-8'),
                    "vaults": {}
                }
                self._save_config(config)
            
            # Verify/correct permissions
            os.chmod(self.vault_dir, 0o700)
            if os.path.exists(self.config_file):
                os.chmod(self.config_file, 0o600)
            
            return True
        except Exception as e:
            print(f"Error initializing secure directory: {str(e)}")
            return False

    def _save_config(self, config):
        """Save configuration securely"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            os.chmod(self.config_file, 0o600)
            return True
        except Exception as e:
            print(f"Error saving configuration: {str(e)}")
            return False

    def _load_config(self):
        """Load configuration"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading configuration: {str(e)}")
            return None

    def _get_encryption_key(self, password):
        """
        Generate an encryption key from the password
        :param password: Password to derive the key from
        :return: Fernet encryption object
        """
        config = self._load_config()
        if not config:
            raise ValueError("Configuration not found")
        
        salt = base64.b64decode(config['salt'].encode('utf-8'))
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def protect_vault_credentials(self, vault_name, vault_token, password):
        """
        Protect Vault token with encryption
        :param vault_name: Name to identify the Vault instance
        :param vault_token: Vault authentication token
        :param password: Password for protecting the credentials
        :return: Boolean indicating success
        """
        try:
            # Encrypt the Vault token
            fernet = self._get_encryption_key(password)
            encrypted_token = fernet.encrypt(vault_token.encode())
            
            # Write only the encrypted token to .vault_env file
            with open(self.vault_env_file, 'w') as f:
                f.write(encrypted_token.decode('utf-8'))
            os.chmod(self.vault_env_file, 0o600)

            # Update config file
            config = self._load_config()
            if not config:
                return False

            config['vaults'][vault_name] = {
                'created': datetime.datetime.now().isoformat(),
                'last_accessed': datetime.datetime.now().isoformat()
            }
            return self._save_config(config)

        except Exception as e:
            print(f"Error protecting Vault credentials: {str(e)}")
            return False

    def load_vault_credentials(self, vault_name, password):
        """
        Load and decrypt Vault token
        :param vault_name: Name of the Vault instance
        :param password: Password to decrypt credentials
        :return: Decrypted Vault token or None
        """
        try:
            if not os.path.exists(self.vault_env_file):
                raise FileNotFoundError("Vault environment file not found")

            # Read encrypted file
            with open(self.vault_env_file, 'r') as f:
                encrypted_token = f.read().strip()

            # Decrypt token
            fernet = self._get_encryption_key(password)
            decrypted_token = fernet.decrypt(encrypted_token.encode('utf-8')).decode()

            # Update last accessed time in config
            config = self._load_config()
            if config and vault_name in config['vaults']:
                config['vaults'][vault_name]['last_accessed'] = datetime.datetime.now().isoformat()
                self._save_config(config)

            return decrypted_token

        except (InvalidToken, ValueError):
            print("Decryption failed. Incorrect password or corrupted data.")
            return None
        except Exception as e:
            print(f"Error loading Vault credentials: {str(e)}")
            return None

    def list_vault_credentials(self):
        """
        List all stored Vault credentials
        :return: Dictionary with Vault credential information
        """
        config = self._load_config()
        return config['vaults'] if config else {}

    def delete_vault_credentials(self, vault_name):
        """
        Delete stored Vault credentials
        :param vault_name: Name of the Vault instance to delete
        :return: Boolean indicating success
        """
        try:
            # Remove .vault_env file
            if os.path.exists(self.vault_env_file):
                os.remove(self.vault_env_file)

            # Update config
            config = self._load_config()
            if config and vault_name in config['vaults']:
                del config['vaults'][vault_name]
                return self._save_config(config)
            return True

        except Exception as e:
            print(f"Error deleting Vault credentials: {str(e)}")
            return False

def print_menu():
    """Print the main menu"""
    print("\n=== Secure Vault Credentials Manager ===")
    print("1. Protect Vault Token")
    print("2. Load Vault Token")
    print("3. List Stored Vault Tokens")
    print("4. Delete Vault Credentials")
    print("0. Exit")
    print("================================")

def main():
    vault_manager = VaultTokenManager()
    
    while True:
        print_menu()
        choice = input("Select an option (0-4): ")
        
        if choice == "0":
            print("\nExiting the program...")
            break
            
        elif choice == "1":
            # Protect new Vault token
            vault_name = input("Enter a name for this Vault instance: ")
            vault_token = input("Enter Vault authentication token: ")
            
            password = getpass("Enter a password to protect the token: ")
            confirm_password = getpass("Confirm the password: ")
            
            if password != confirm_password:
                print("Passwords do not match!")
                continue
            
            if vault_manager.protect_vault_credentials(vault_name, vault_token, password):
                print("\nVault token protected successfully!")
            else:
                print("\nError protecting Vault token")
                
        elif choice == "2":
            # Load Vault token
            try:
                vault_name = input("Enter the name of the Vault instance: ")
                password = getpass("Enter the password to decrypt the Vault token: ")
                vault_token = vault_manager.load_vault_credentials(vault_name, password)
                
                if vault_token:
                    print(vault_token)  # Masked for security
                else:
                    print("\nFailed to load Vault token")
                    
            except Exception as e:
                print(f"\nError: {str(e)}")
                
        elif choice == "3":
            # List stored Vault credentials
            stored_vaults = vault_manager.list_vault_credentials()
            if stored_vaults:
                print("\nStored Vault Credentials:")
                for name, info in stored_vaults.items():
                    print(f"\nName: {name}")
                    print(f"Created: {info['created']}")
                    print(f"Last Accessed: {info['last_accessed']}")
            else:
                print("\nNo Vault credentials found")
                
        elif choice == "4":
            # Delete Vault credentials
            vault_name = input("Enter the name of the Vault instance to delete: ")
            
            confirm = input(f"Are you sure you want to delete credentials for {vault_name}? (y/N): ")
            if confirm.lower() == 'y':
                if vault_manager.delete_vault_credentials(vault_name):
                    print(f"\nVault credentials for {vault_name} deleted successfully!")
                else:
                    print("\nError deleting Vault credentials")
            else:
                print("\nOperation cancelled")
                
        else:
            print("\nInvalid option!")
        
        input("\nPress ENTER to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")