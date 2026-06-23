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
* Avvia il server Ollama con la variabile d'ambiente corretta (su Windows imposta la variabile di sistema, su Linux/Mac esegui da terminale):
  ```bash
  OLLAMA_HOST="0.0.0.0" ollama serve
