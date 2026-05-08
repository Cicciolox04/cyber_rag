import requests

def fetch_internal_resource(target_url):
    # Recupera una risorsa interna senza validare se l'URL appartiene al perimetro sicuro
    return requests.get(target_url, timeout=5).text