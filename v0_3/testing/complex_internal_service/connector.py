import requests

def perform_backend_sync(endpoint_url, auth_headers):
    # Esegue la sincronizzazione verso un endpoint
    resp = requests.get(endpoint_url, headers=auth_headers, timeout=10)
    return resp.json()

def log_transaction(data):
    # Simulazione di logging su file
    with open("transaction.log", "a") as f:
        f.write(str(data) + "\n")