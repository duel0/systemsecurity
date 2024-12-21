#!/bin/bash

# Controlla che sia stato passato il token come parametro
if [ -z "$1" ]; then
    echo "Errore: Devi fornire il VAULT_TOKEN come primo parametro."
    echo "Uso: ./setup_vault.sh <VAULT_TOKEN>"
    exit 1
fi

# Configura le variabili d'ambiente per Vault
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN="$1"

# Abilita il motore Transit
vault secrets enable transit
vault write -f transit/keys/document-key

# Abilita il motore Database
vault secrets enable database

# Configura il plugin PostgreSQL per il motore Database
vault write database/config/docsecure \
    plugin_name=postgresql-database-plugin \
    allowed_roles="app-role" \
    connection_url="postgresql://{{username}}:{{password}}@localhost:5432/docsecure?sslmode=disable" \
    username="docsecure_app" \
    password="initial_password" 

# Crea il ruolo per l'applicazione
vault write database/roles/app-role \
    db_name=docsecure \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Abilita il motore KV su un percorso personalizzato
vault secrets enable -path=keycloak kv-v2

# Scrivi i segreti nel motore KV
vault kv put keycloak/config \
    server_url='http://localhost:8081' \
    realm_name='AlFrescoRealm' \
    client_id='AlFrescoClient' \
    client_secret='D4gLfeTOKkivPAy5kQPGrDxgyJVnDRv6' \
    redirect_uri='https://localhost:5173' \
    protected_role='AdminRole' \
    mydocs_roles='AdminRole+UserRole' \
    shared_roles='AdminRole+UserRole' \
    download_roles='AdminRole+UserRole' \
    upload_roles='AdminRole+UserRole' \
    ssl_pass='alfresco'

echo "Configurazione completata con successo."