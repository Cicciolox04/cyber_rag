from settings import AppConfig
from connector import perform_backend_sync, log_transaction

class SyncManager:
    def __init__(self):
        self.config = AppConfig()

    def process_remote_sync(self, remote_path):
        headers = self.config.get_headers()
        
        # Costruzione della rotta di destinazione
        final_target = f"{self.config.base_url}/{remote_path}"
        
        # Esecuzione
        result = perform_backend_sync(final_target, headers)
        log_transaction(result)
        
        return result