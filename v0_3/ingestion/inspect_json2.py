import json
import os
from pprint import pprint

def explore_structure(file_path):
    print(f"🕵️ Analisi profonda di: {file_path}\n" + "-"*50)
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Identifichiamo la chiave principale (abbiamo visto che è cve_items)
    items = data.get('cve_items', [])
    
    if not items:
        print("❌ Nessun elemento trovato in 'cve_items'.")
        return

    # Prendiamo il primo elemento come campione
    sample = items[0]
    
    print("📂 CHIAVI DI PRIMO LIVELLO NELL'ELEMENTO:")
    for key in sample.keys():
        val_type = type(sample[key]).__name__
        # Se è una stringa o numero, mostriamo il valore, altrimenti mostriamo la struttura
        if isinstance(sample[key], (str, int, float)):
            print(f"  - {key} ({val_type}): {sample[key]}")
        else:
            print(f"  - {key} ({val_type}): {list(sample[key].keys()) if isinstance(sample[key], dict) else 'Lista'}")

    print("\n🧐 CAMPIONE COMPLETO DEL PRIMO RECORD (Sotto-chiavi incluse):")
    pprint(sample, depth=3)

if __name__ == "__main__":
    # Proviamo con il file 2022
    target = "../data/cve_data/CVE-2022.json"
    if os.path.exists(target):
        explore_structure(target)
    else:
        print(f"❌ File {target} non trovato.")