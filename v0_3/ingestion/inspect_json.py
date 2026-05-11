import json
import os

def find_cwe_path(obj, path=""):
    """
    Esplora ricorsivamente il JSON alla ricerca della stringa 'CWE-'.
    Restituisce il percorso per arrivare al valore.
    """
    results = []
    
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path} -> ['{k}']" if path else f"['{k}']"
            results.extend(find_cwe_path(v, new_path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_path = f"{path} -> [{i}]"
            results.extend(find_cwe_path(v, new_path))
    elif isinstance(obj, str):
        if "CWE-" in obj:
            results.append(f"🎯 TROVATO! Valore: '{obj}' | Percorso: {path}")
            
    return results

def inspect_first_entry(file_path):
    print(f"🕵️ Ispezione del file: {file_path}")
    if not os.path.exists(file_path):
        print("❌ File non trovato!")
        return

    with open(file_path, 'r') as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"❌ Errore nel caricamento JSON: {e}")
            return

    # Se il file è una lista enorme o un dizionario con molte chiavi,
    # analizziamo solo un campione per non intasare il terminale.
    sample = None
    if isinstance(data, list):
        sample = data[0]
        print("📝 Struttura rilevata: LISTA")
    elif isinstance(data, dict):
        # Cerchiamo le chiavi principali comuni (vulnerabilities, CVE_Items)
        key = 'vulnerabilities' if 'vulnerabilities' in data else ('CVE_Items' if 'CVE_Items' in data else None)
        if key and len(data[key]) > 0:
            sample = data[key][0]
            print(f"📝 Struttura rilevata: DIZIONARIO con chiave '{key}'")
        else:
            sample = data
            print("📝 Struttura rilevata: DIZIONARIO generico")

    if sample:
        findings = find_cwe_path(sample)
        if findings:
            for f in findings[:5]: # Mostra i primi 5 percorsi trovati
                print(f)
        else:
            print("⚠️ Nessuna stringa 'CWE-' trovata nel campione analizzato.")
    else:
        print("⚠️ Il file sembra vuoto o non interpretabile.")

if __name__ == "__main__":
    # Sostituisci con uno dei tuoi file scaricati
    target_file = "../data/cve_data/CVE-2022.json" 
    inspect_first_entry(target_file)