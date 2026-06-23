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

### 2. Configurazione Neo4j

