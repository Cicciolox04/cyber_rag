import requests
import os

def install_update():
    # VULNERABILITÀ: Download su HTTP e esecuzione diretta
    url = "http://repo.external-service.io/v3/updates/patch.bin"
    response = requests.get(url)
    
    with open("patch.bin", "wb") as f:
        f.write(response.content)
    
    # Esecuzione del binario scaricato senza validazione
    os.system("chmod +x patch.bin && ./patch.bin")

if __name__ == "__main__":
    install_update()