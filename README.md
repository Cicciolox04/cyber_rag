# 🛡️ Graph RAG per Cyber Threat Intelligence (SOC Tier 1 AI Agent)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Neo4j](https://img.shields.io/badge/Neo4j-Graph_Database-blue)
![Ollama](https://img.shields.io/badge/Ollama-Llama_3-black)
![Gradio](https://img.shields.io/badge/UI-Gradio-orange)

Questo repository contiene il codice sorgente sviluppato per il mio progetto di tesi. Il sistema implementa un'architettura **Graph RAG** (Retrieval-Augmented Generation basata su grafi) per l'analisi automatizzata di vulnerabilità infrastrutturali (scansioni Nmap) e la risposta reattiva agli incidenti (Log Web).

L'obiettivo del progetto è risolvere le "allucinazioni" e il *Context Bleeding* tipici dei Large Language Models (LLM) in ambito cybersecurity, costringendo il modello a ragionare su percorsi logici predefiniti e ancorati a standard internazionali.

## ✨ Funzionalità Principali

- **Determinismo Topologico:** Utilizza Neo4j come *Knowledge Graph* per mappare le relazioni esatte tra CVE, CWE, CAPEC, MITRE ATT&CK e OpenCRE.
- **Prevenzione Allucinazioni:** Se non esiste un collegamento nel grafo, il modello non inventa normative o tattiche inesistenti (prevenzione della *Compliance Fallacy*).
- **Structured Output Parsing:** Utilizza pipeline ibride con `JsonOutputParser` di LangChain e tecniche di *Chain of Thought* (CoT) per estrarre artefatti dai log rumorosi.
- **Normalizzazione Sintattica UI:** Implementa algoritmi basati su *Regex* per stabilizzare l'output del modello quantizzato (Llama 3) e renderizzarlo correttamente nella dashboard Gradio.
- **Analisi Multi-Scenario:** Supporta sia l'analisi preventiva (`.nmap` XML/TXT) sia quella reattiva (Apache/Nginx `.log`).

---

## ⚠️ ATTENZIONE: Caricamento Manuale delle CVE

A causa delle limitazioni di dimensione dei file su GitHub (e per mantenere il repository leggero), **il database Neo4j popolato con l'intero catalogo delle CVE non è incluso in questo repository.** 

Per far funzionare correttamente il *Graph Traversal*, è necessario popolare manualmente il database Neo4j prima di avviare l'applicazione:
1. Assicurarsi di avere un'istanza Neo4j in esecuzione.
2. Scaricare o generare il dataset delle vulnerabilità.
3. Importare i nodi e le relazioni (CVE $\rightarrow$ CWE $\rightarrow$ CAPEC, ecc.) all'interno del database (utilizzando gli script di ingestion forniti nella cartella `/scripts` o ripristinando un dump locale).

---

## 🛠️ Prerequisiti

Per eseguire il progetto in locale, è necessario avere installato:

- **Python 3.10+**
- **Neo4j Desktop / Server** (versione 5.x raccomandata)
- **Ollama** (per l'esecuzione in locale del modello LLM)
- Il modello Llama 3 quantizzato:
```bash
  ollama run llama3
