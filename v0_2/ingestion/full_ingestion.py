import subprocess
import sys

# Lista degli script in ordine logico di esecuzione
scripts = [
    "reset_db.py",
    "ingest_mitre.py",
    "ingest_cwe.py",
    "ingest_capec.py"
]

def run_ingestion():
    print("🏁 Inizio procedura di aggiornamento database RAG...")
    
    for script in scripts:
        print(f"\n▶️ Esecuzione di: {script}")
        result = subprocess.run([sys.executable, script], capture_output=False)
        
        if result.returncode != 0:
            print(f"❌ Errore durante l'esecuzione di {script}. Procedura interrotta.")
            return

    print("\n✨ Database aggiornato e pronto per la demo!")

if __name__ == "__main__":
    run_ingestion()