# cn=admin,dc=ramhlocal,dc=com

from ldap3 import Server, Connection, Entry
import json

# Configurazione del server LDAP
server = Server('openldap', port=389)

# Connessione al server LDAP
with Connection(server, user='cn=admin,dc=ramhlocal,dc=com', password='admin_pass') as conn:

    print("Inserisci le crednziali del nuovo utente")
    username = input("Username: ")
    password = input("Password: ")
    
    dn = "cn=%s,dc=ramhlocal,dc=com" % username  # DN della nuova entry
    attributes = {
        'objectClass': ['simpleSecurityObject', 'person'],
        'cn': 'new_user',
        'sn': 'user_surname',
        'userPassword': password,
        'description': 'user'
    }

    # Aggiungi la nuova entry
    conn.add(dn, attributes=attributes)

    # Effettua la ricerca nel server LDAP
    conn.search('dc=ramhlocal,dc=com', '(objectClass=person)')

    # Stampa i risultati della ricerca
    for entry in conn.entries:
        print(entry.entry_to_json())
        if 'new_user' in json.loads(entry.entry_to_json())['dn']:
            print('user')
