from flask import Flask, request, jsonify
from core_logic import SyncManager

app = Flask(__name__)
manager = SyncManager()

@app.route('/v1/sync', methods=['POST'])
def sync_handler():
    # Riceve il percorso dal corpo della richiesta
    user_data = request.json
    path_suffix = user_data.get('target_path')
    
    try:
        status = manager.process_remote_sync(path_suffix)
        return jsonify({"status": "completed", "data": status})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)