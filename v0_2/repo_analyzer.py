import os
from langchain_ollama import ChatOllama

# --- CONFIGURAZIONE ---
REPO_PATH = "repo/" # Metti qui il path della cartella da testare
URL_OLLAMA = "http://10.0.2.2:11434"

def scan_and_summarize(path):
    allowed_ext = [".py", ".c", ".cpp", ".js", ".h"]
    files_content = []
    
    print(f"📁 Scansione della cartella: {path}")
    
    for root, dirs, files in os.walk(path):
        # Escludiamo cartelle spazzatura
        dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__']]
        
        for file in files:
            if any(file.endswith(ext) for ext in allowed_ext):
                rel_path = os.path.relpath(os.path.join(root, file), path)
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    files_content.append(f"--- FILE: {rel_path} ---\n{content}")

    return "\n\n".join(files_content)

def run_repo_analysis():
    # 1. Estrazione di tutti i file nel repo
    repo_context = scan_and_summarize(REPO_PATH)
    
    if not repo_context:
        print("❌ Nessun file di codice trovato.")
        return

    # 2. Inizializzazione LLM
    llm = ChatOllama(model="mistral", base_url=URL_OLLAMA, temperature=0.1)

    # 3. Prompt di Analisi Strutturale
    prompt = f"""
    Sei un Security Auditor. Analizza il seguente repository di codice e identifica potenziali problemi di sicurezza strutturali.
    Focalizzati su:
    - Flusso dei dati tra i file.
    - Gestione delle configurazioni.
    - Vulnerabilità logiche.

    CONTENUTO REPOSITORY:
    {repo_context[:8000]} # Limitiamo il contesto per non saturare la memoria

    RISPONDI CON:
    1. ARCHITETTURA: Breve descrizione di come è strutturato il codice.
    2. VULNERABILITÀ INDIVIDUATE: Elenco dei file e delle righe sospette.
    3. RACCOMANDAZIONI: Come migliorare la sicurezza globale del progetto.
    """

    print("🤖 Analisi del repository in corso...")
    response = llm.invoke(prompt)
    print("\n--- REPORT DI AUDIT REPOSITORY ---")
    print(response.content)

if __name__ == "__main__":
    run_repo_analysis()