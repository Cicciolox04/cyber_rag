from internal_fetcher import fetch_internal_resource

def proxy_request(user_provided_url):
    
    data = fetch_internal_resource(user_provided_url)
    return {"status": "success", "content": data}