from flask import Flask, redirect, url_for, session, request, render_template, flash

from flask_session import Session           # per gestire le sessioni lato flask

from urllib.parse import urlencode
from libdocs import DocumentService
import psycopg2
import requests
import jwt              # per gestire i Json Web Token
import logging          # gestione del debugging
from vault_setup import VaultTokenManager
from getpass import getpass
from key_security import KeySecurityManager

###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### 
###### ###### ###### ######           WEB APP CONFIGURATION           ###### ###### ###### ###### 
###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### 

# creazione istanza app by Flask




app = Flask(__name__)
app.config['SESSION_TYPE'] = "filesystem"                           # la sessione deve essere memorizzata su filesystem (cioè in una cartella del progetto)
Session(app)


vtmanager = VaultTokenManager()

try:
    vault_name = input("Enter the name of the Vault instance: ")
    password = getpass("Enter the password to decrypt the Vault token: ")
    vault_token = vtmanager.load_vault_credentials(vault_name, password)
    print("\nVault token loaded successfully.")
        
except Exception as e:
    print(f"\nError: {str(e)}")


doc_service = DocumentService(
    vault_url="http://127.0.0.1:8200",
    vault_token=vault_token,
    db_connection=None
)

try:
    db_creds = doc_service.vault_client.read('database/creds/app-role')
    conn = psycopg2.connect(
        dbname=db_creds['data']['dbname'],
        user=db_creds['data']['username'],  
        password=db_creds['data']['password'],              
        host=db_creds['data']['localhost'],
        sslmode=db_creds['data']['sslmode'],
        gsslib=None
    )
    doc_service.db_connection = conn
except:
    print("Error reading database credentials from Vault")


logging.basicConfig(level=logging.DEBUG)  



secret = doc_service.vault_client.secrets.kv.v2.read_secret_version(
    mount_point="keycloak",  
    path="config"            
)

keycloak_config = secret['data']['data']
    
keycloak_server_url = keycloak_config['server_url']
realm_name = keycloak_config['realm_name']
client_id = keycloak_config['client_id']
client_secret = keycloak_config['client_secret']
redirect_uri = keycloak_config['redirect_uri']

# Homepage
@app.route('/')
def index():
    msg=''
    if session.get('user') != None:
        username=session['user']['username']
        msg = f"Benvenuto, {username}!"   # Se c'è un utente loggato, ne mostra lo username

    return render_template('index.html', welcome_msg=msg)


###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### 
###### ###### ###### ######          DECORATOR LOGIN_REQUEST          ###### ###### ###### ###### 
###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### 


# Funzione che verifica se la sessione dell'utente è ancora attiva:
#  ogni volta che l'utente tenta di accedere a una pagina protetta (le quali pagine sono definite nel 
#  decorator "required_login", viene fatta una verifica attiva della sessione interagendo con keycloak, 
#  così da rendere sicura l'app anche in caso di disallineamenti tra la sessione di flask e quella di keycloak.
#  Inoltre, gestisce anche l'aggiornamento dei token usando il refresh token (se l'access token scade, ma la 
#  sessione in keycloak è ancora attiva - quest'ultima infatti dura 30 minuti). 
def is_authenticated():
    if 'user' not in session:
        return False
    
    try:
        userinfo_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/userinfo"
        headers = {'Authorization': f"Bearer {session['user']['access_token']}"}
        response = requests.get(userinfo_endpoint, headers=headers)

        if response.status_code == 200: # l'access token è ancora valido
            return True # quindi anche la sessione è ancora valida

        elif response.status_code == 401: # l'access token non è più valido
            logging.info("Access token scaduto, tentativo di refresh...")
            refresh_token = session['user']['refresh_token']
            token_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/token"
            payload = { 'client_id': client_id, 'grant_type': 'refresh_token', 'refresh_token': refresh_token, 'client_secret': client_secret}
            token_response = requests.post(token_endpoint, data=payload)
            if token_response.status_code == 200: # ma il refresh token è ancora valido
                new_tokens = token_response.json()
                session['user']['access_token'] = new_tokens['access_token']
                session['user']['refresh_token'] = new_tokens['refresh_token']
                session['user']['id_token'] = new_tokens['id_token']
                logging.info("Token aggiornati con successo.")
                return True # quindi anche la sessione è ancora valida
            else: # se nemmeno il refresh token è valido
                logging.error(f"Errore nel refresh token: {token_response.json()}")
                session.clear()
                return False # allora la sessione non è più valida
        else:
            logging.error(f"Error verifying token. Error code: {response.status_code}")
            session.clear()
            return False

    except Exception as e:
        logging.error(f"Error checking session with Keycloak: {e}")
        session.clear()
        return False


# Decoratore che definisce le pagine che devono essere protette
#  flask offre questo decoratore che viene richiamato prima di tutte le richieste verso le rotte definite 
#  in questa app. All'interno di questo decoratore viene usata la funzione "is_authenticated" definita sopra.
@app.before_request
def login_required():
    allowed_routes = ['index', 'login', 'callback']  # queste sono le rotte che possono essere visitate senza login
    if request.endpoint not in allowed_routes:
        if not is_authenticated():
            return redirect(url_for('login'))


###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### 
###### ###### ###### ######              LOGIN E LOGOUT               ###### ###### ###### ###### 
###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### 


# Funzione di login:
#  keycloak offre un endpoint per il login, a cui però bisogna inviare anche alcuni parametri per capire 
#  di quale client si tratta, a quale url keycloak deve tornare, il tipo di interazione con il client (il 1°)
#  e gli scope.
@app.route('/login')
def login():
    authorize_url = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/auth"
    redirect_uri_callback = f"{redirect_uri}/callback"
    params = { 'client_id': client_id, 'redirect_uri': redirect_uri_callback, 'response_type': 'code', 'scope': 'openid profile email' }

    return redirect(f"{authorize_url}?{'&'.join([f'{key}={value}' for key, value in params.items()])}")


# Funzione di callback per il login:
#  dopo aver contattato keycloak per fare il login (con la funzione precedente), keycloak risponde a questo 
#  url aggiungendogli dei parametri, i quali devono essere prelevati per creare la sessione dell'utente lato 
#  flask. Precisamente prima bisogna contattare l'endpoint per ottenere i token, e poi bisogna contattare 
#  l'endpoint per ottenere le info dell'utente appena autenticato.
@app.route('/callback')
def callback():
    code = request.args.get('code') # keycloak, dopo aver eseguito il login, reindirizza il browser verso questo url, cioè "/callback", ma oltre a questa rotta contiene anche altri argomenti (tra cui il "code"). la funzione "request.args" prende gli argomenti dopo il "?" nell'url e li mette in un dizionario; in questo caso prende direttamente il parametro "code" dal dizionario
    logging.debug(f"Callback received with code: {code}")
    token_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/token"
    redirect_uri_callback = f"{redirect_uri}/callback"
    payload = { 'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri_callback, 'client_id': client_id, 'client_secret': client_secret}

    try:
        response = requests.post(token_endpoint, data=payload) # l'app fa una richiesta verso keycloak, precisamente verso il suo token endpoint; è una funzione bloccante, quindi aspetta la risposta e una volta arrivata viene messa in "response"
        logging.debug(f"payload: {response}")
        token_data = response.json() # la risposta di keycloak viene convertita in json
        
        if 'access_token' in token_data: #se nella risposta c'è "access_token", lo uso per prelevare le "userinfo" dal relativo endpoint
            userinfo_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/userinfo"
            headers={'Authorization': f"Bearer {token_data['access_token']}"}
            userinfo_response = requests.get(userinfo_endpoint, headers=headers)
            userinfo = userinfo_response.json()
            session['user'] = {
                'id_token': token_data.get('id_token'),
                'access_token': token_data.get('access_token'),
                'refresh_token': token_data.get('refresh_token'),
                'username': userinfo.get('preferred_username'),
                'email': userinfo.get('email')
            }

            logging.debug("User logged in successfully.")
            return redirect(url_for('index'))
        else:
            logging.error("Failed to fetch tokens.")
            return "Failed to fetch tokens."

    except Exception as e:
        logging.error(f"Exception during token exchange: {e}")
        return "Failed to fetch tokens."


# Funzione di logout:
#  keycloak offre un endpoint apposito per il logout, a cui però bisogna inviare anche alcuni parametri per 
#  assicurarsi di chiudere correttamente la sessione lato keycloak (cioè id_token_hint). Invece per chiudere 
#  la sessione lato flask viene usata l'istruzione "session.clear".
@app.route('/my_logout')
def my_logout():
    logging.debug('Attempting to logout...')

    try:
        end_session_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/logout"

        id_token = session['user']['id_token']        
        redirect_uri = 'http://localhost:5173/'
        params = { 'client_id': client_id, 'id_token_hint': id_token, 'post_logout_redirect_uri': redirect_uri}

        session.clear()
        logging.debug('Flask session cleared. Redirecting to login...')

        response = requests.get(end_session_endpoint + '?' + urlencode(params))
        return redirect(url_for('index'))

    except requests.exceptions.RequestException as e:
        logging.error(f"Exception during logout: {e}")
        return "Failed to logout. Please try again."



###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ###### ######



def get_user_roles():
    if 'user' not in session:
        return []

    try:
        access_token = session['user']['access_token']
        decoded_token = jwt.decode(access_token, options={"verify_signature": False}) # decodifico l'access token senza verificare la firma
        client_roles = decoded_token.get('realm_access', {}).get('roles', []) # recupero i ruoli del realm
        return client_roles

    except Exception as e:
        logging.error(f"Error decoding token: {e}")
        return []



@app.route('/protected')
def admin_page():
    if 'user' not in session:
        return "Access Denied: you are not logged in.", 403
    
    username = session['user']['username']
    roles = get_user_roles()
    logging.debug(f"Roles: {roles}")

    
    if keycloak_config['protected_role'] in roles:
        documents = doc_service.list_all_documents()
        print(documents)
        return render_template('all_docs.html', username=username, documents=documents)
    
    else:
        return "Access Denied: you are not an admin.", 403


    
    




@app.route('/my_docs')
def my_docs():
    if 'user' not in session:
        return "Access Denied: you are not logged in.", 403
    username = session['user']['username']  # Assuming session['user'] contains 'username'
    roles = get_user_roles()
    logging.debug(f"Roles: {roles}")

    
    allowlist = keycloak_config['mydocs_roles'].split('+')
    if any(role in roles for role in allowlist):
        documents = doc_service.list_documents(username)
        print(documents)
        return render_template('my_docs.html', username=username, documents=documents)


@app.route('/shared')
def shared():
    if 'user' not in session:
        return "Access Denied: you are not logged in.", 403
    roles = get_user_roles()
    logging.debug(f"Roles: {roles}")
    allowlist = keycloak_config['shared_roles'].split('+')
    if any(role in roles for role in allowlist):
        username = session['user']['username']  
        documents = doc_service.list_shared_documents()
        print(documents)
        return render_template('shared_docs.html', username=username, documents=documents)


@app.route('/download_doc/<int:doc_id>')
def download_doc(doc_id):
    if 'user' not in session:
        return "Access Denied: you are not logged in.", 403
    roles = get_user_roles()
    logging.debug(f"Roles: {roles}")
    allowlist = keycloak_config['download_roles'].split('+')
    if any(role in roles for role in allowlist):
        username = session['user']['username']
        doc = doc_service.get_document(doc_id, username)
        
        with open(f'/Users/balassone/Downloads/{doc_id}.pdf', 'wb') as f:
            f.write(doc['content'])
        return redirect(url_for('my_docs'))



@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return "Access Denied: you are not logged in.", 403
    roles = get_user_roles()
    logging.debug(f"Roles: {roles}")
    allowlist = keycloak_config['upload_roles'].split('+')
    if any(role in roles for role in allowlist):
        if request.method == 'POST':
            
            if 'file' not in request.files or request.files['file'].filename == '':
                flash('No file selected.')
                return redirect(request.url)
            
            file = request.files['file']
            filename = file.filename
            content = file.read()
            username = session['user']['username']  

            
            shared = 'shared' in request.form and request.form['shared'] == 'on'
            try:
                doc_service.store_document(filename, content, username, shared=shared)
                flash('Document uploaded successfully!')
                return redirect('/my_docs')
            except Exception as e:
                flash(f"Error uploading document: {str(e)}")
                return redirect(request.url)
        return render_template('upload.html')


    


if __name__ == '__main__':
    sslkey = KeySecurityManager()
    #sslkeypass = getpass("Enter the password to decrypt the SSL private key: ")
    key_data = sslkey.retrieve_key('user',keycloak_config['ssl_pass'])
    if key_data:
        save_path = 'localhost.key'
        with open(save_path, 'wb') as f:
            f.write(key_data)
    app.run(host='127.0.0.1', port=5173, debug=True,ssl_context=('localhost.crt', 'localhost.key'))
