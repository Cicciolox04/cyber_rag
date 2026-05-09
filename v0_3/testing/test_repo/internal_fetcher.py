import requests

def fetch_internal_resource(target_url):
    
    return requests.get(target_url, timeout=5).text