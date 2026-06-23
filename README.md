# 🛡️ Graph RAG per Cyber Threat Intelligence

![OS](https://img.shields.io/badge/OS-Kali_Linux_(VM)-black?logo=kali-linux)
![Host](https://img.shields.io/badge/Host-Neo4j_&_Ollama-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Gradio](https://img.shields.io/badge/UI-Gradio-orange)

Questo repository contiene il codice sorgente sviluppato per il mio progetto di tesi. Il sistema implementa un'architettura **Graph RAG** ibrida (Retrieval-Augmented Generation basata su grafi) per l'analisi automatizzata di vulnerabilità infrastrutturali e la risposta reattiva agli incidenti.

## ⚠️ ATTENZIONE: Topologia Ibrida e Requisiti

1. **Esecuzione Applicativa su Kali Linux:** L'agente Python e l'interfaccia UI sono progettati per funzionare **ESCLUSIVAMENTE su Kali Linux** (eseguito in Macchina Virtuale). L'architettura è strettamente accoppiata agli strumenti di sicurezza offensiva nativi di Kali.
2. **Motori Backend su Host:** Per garantire le massime prestazioni, il database a grafo (Neo4j) e i modelli generativi (Ollama) **devono essere eseguiti sul sistema Host** (Windows/macOS/Linux), esponendo i servizi alla VM.
3. **Database CVE Assente dal Repo:** A causa dei limiti di dimensione, il database Neo4j popolato con l'intero catalogo CVE non è incluso e i feed NVD devono essere scaricati manualmente.

---

## ⚙️ Configurazione Sistema HOST (Database e LLM)

Sul tuo sistema Host fisico (fuori dalla VM), configura e avvia i servizi backend:

### 1. Configurazione Ollama
Ollama deve essere configurato per accettare connessioni dall'esterno (dalla VM) esponendo l'host su `0.0.0.0`.
* Installare Ollama direttamente dal browser (https://ollama.com/download)
* Assicurati che il server Ollama sia spento, dopodiché configura le variabili d'ambiente inserendo una nuova variabile OLLAMA_HOST con valore: 0.0.0.0
* Riavvia il server digitando direttamente dalla barra di ricerca Windows e cercando "Ollama"
* Avvia un terminale e digitare:
  ```bash
  ollama pull llama3
  ollama pull mxbai-embed-large

### 2. Configurazione Neo4j Borwser Desktop
* Scaricare ed installare Neo4j Browser Desktop dal browser (https://neo4j.com/download)
* Creare una istanza e modificare il file neo4j.config decommentando o aggiungendo queste sezioni:
  ```bash
  server.default_listen_address=0.0.0.0
  server.bolt.listen_address=0.0.0.0:7687
  server.http.listen_address=0.0.0.0:7474
* Riavvia il servizio Neo4j

## 🚀 Configurazione Macchina Virtuale (KALI LINUX)
**Step 1: Configurazione Rete NAT e Port Forwarding**
Nelle impostazioni del tuo hypervisor (es. VirtualBox, VMware), imposta la scheda di rete della VM Kali su NAT.
Per poter visualizzare la dashboard di Gradio dal browser del tuo Host, aggiungi questa singola regola di Port Forwarding:

Gradio UI | Protocollo TCP | Porta Host: 7860 | Porta Guest: 7860

**Step 2: Clonazione e Setup Ambiente**
Avvia Kali Linux, apri il terminale e clona il repository:
  ```bash
  git clone https://github.com/Cicciolox04/cyber_rag.git
  cd cyber_rag
  
  # Crea un ambiente virtuale
  python3 -m venv venv
  
  # Insalla le dipendenze
  pip install -r requirements.txt
```
**Step 3: Download Manuale delle CVE (NVD JSON Feeds)**



