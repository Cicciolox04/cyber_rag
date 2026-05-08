from internal_fetcher import fetch_internal_resource

def proxy_request(user_provided_url):
    # L'utente può passare "http://localhost:8080/admin" o "http://169.254.169.254" (Metadata Cloud)
    data = fetch_internal_resource(user_provided_url)
    return {"status": "success", "content": data}