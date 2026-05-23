import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping_host():
    
    target = request.args.get('target')
    
    
    comando = "ping -c 1 " + target
    risultato = subprocess.check_output(comando, shell=True)
    
    return risultato

if __name__ == '__main__':
    app.run(debug=True)