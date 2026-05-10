class AppConfig:
    def __init__(self):
        self.internal_api_key = "sk-internal-7721-prod-key-99"
        self.base_url = "http://internal.backup.local/api/v2"
        self.debug_mode = True

    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.internal_api_key}",
            "Content-Type": "application/json"
        }