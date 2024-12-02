import base64
import hvac
import os
from datetime import datetime
import psycopg2

class DocumentService:
    def __init__(self, vault_url, vault_token, db_connection):
        # Inizializza client Vault
        self.vault_client = hvac.Client(
            url=vault_url,
            token=vault_token
        )
        self.db_connection = db_connection

    def encrypt_file(self, file_content):
        # Converte il contenuto in base64
        encoded_content = base64.b64encode(file_content).decode('utf-8')
        
        # Cifra usando Vault Transit
        encrypt_data = self.vault_client.secrets.transit.encrypt_data(
            name='document-key',
            plaintext=encoded_content
        )
        return encrypt_data['data']['ciphertext']

    def decrypt_file(self, encrypted_content):
        # Decifra usando Vault Transit
        decrypt_data = self.vault_client.secrets.transit.decrypt_data(
            name='document-key',
            ciphertext=encrypted_content
        )
        # Decodifica da base64
        return base64.b64decode(decrypt_data['data']['plaintext'])

    def store_document(self, filename, content, owner):
        try:
            encrypted_content = self.encrypt_file(content)
            with self.db_connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO documents 
                    (filename, content_encrypted, content_type, file_size, owner)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    filename,
                    encrypted_content,
                    self._get_content_type(filename),
                    len(content),
                    owner
                ))
                doc_id = cur.fetchone()[0]
                self.db_connection.commit()
                return doc_id
        except Exception as e:
            self.db_connection.rollback()
            raise Exception(f"Failed to store document: {str(e)}")

    def get_document(self, doc_id, user):
        with self.db_connection.cursor() as cur:
            cur.execute("""
                SELECT content_encrypted, filename 
                FROM documents 
                WHERE id = %s AND (owner = %s OR shared = true)
            """, (doc_id, user))
            
            result = cur.fetchone()
            if not result:
                raise ValueError("Document not found or access denied")
                
            encrypted_content, filename = result
            return {
                'content': self.decrypt_file(encrypted_content),
                'filename': filename
            }

    def _get_content_type(self, filename):
        # Semplice rilevamento del content type basato sull'estensione
        ext = os.path.splitext(filename)[1].lower()
        content_types = {
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            # aggiungi altri tipi secondo necessità
        }
        return content_types.get(ext, 'application/octet-stream')
    def share_document(self, doc_id, owner, share=True):
        with self.db_connection.cursor() as cur:
            cur.execute("""
                UPDATE documents 
                SET shared = %s 
                WHERE id = %s AND owner = %s
                RETURNING id
            """, (share, doc_id, owner))
            self.db_connection.commit()
            return cur.fetchone() is not None

    def list_documents(self, user):
        with self.db_connection.cursor() as cur:
            cur.execute("""
                SELECT id, filename, file_size, created_at, shared 
                FROM documents 
                WHERE owner = %s
                ORDER BY created_at DESC
            """, (user,))
            return cur.fetchall()
        
        '''cur.execute("""
                SELECT id, filename, file_size, created_at, shared 
                FROM documents 
                WHERE owner = %s OR shared = true
                ORDER BY created_at DESC
            """, (user,))
            return cur.fetchall()'''
    

# Connessione al DB (usando le credenziali generate da Vault)
# vault read database/creds/app-role
'''
conn = psycopg2.connect(
    dbname="docsecure",
    user="v-root-app-role-7VWoNs5RQFzAzGCExics-1733053165",  # username da Vault
    password="cFu8l7El-QHenqxbeRTk",              # password da Vault
    host="localhost"
)

# Inizializza il service
# vault server -dev
doc_service = DocumentService(
    vault_url='http://127.0.0.1:8200',
    vault_token='hvs.SHX8pREMTW8megySRcEq3y4r',
    db_connection=conn
)
'''
'''
# Esempio: salva un documento
with open('ciao.pdf', 'rb') as f:
    content = f.read()
    doc_id = doc_service.store_document('ciao.pdf', content, 'user1')

# Esempio: recupera un documento
doc = doc_service.get_document(doc_id, 'user1')
with open('recovered_' + doc['filename'], 'wb') as f:
    f.write(doc['content'])

    '''