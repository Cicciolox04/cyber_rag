import requests

def login_to_api():

    username = "admin"
    password = "SuperSecretPassword123!"
    
    url = "http://internal-api.local/v1/auth"
    response = requests.post(url, auth=(username, password))
    
    if response.status_code == 200:
        print("Login effettuato con successo.")

login_to_api()