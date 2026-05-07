import requests
import config

def sync_database():
    print(f"Avvio sincronizzazione API {config.API_VERSION}...")
    
    # Utilizzo delle credenziali importate da config.py
    payload = {
        "user": config.DB_USER,
        "token": config.DB_PASS
    }
    
    try:
        # VULNERABILITÀ: Invio di credenziali in chiaro su protocollo HTTP
        response = requests.post(config.BACKUP_SERVER, json=payload, timeout=5)
        
        if response.status_code == 200:
            print("Sincronizzazione completata con successo.")
        else:
            print(f"Errore server: {response.status_code}")
            
    except Exception as e:
        print(f"Errore di connessione: {e}")

if __name__ == "__main__":
    sync_database()