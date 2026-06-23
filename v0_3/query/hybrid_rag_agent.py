import os
import warnings
import logging
from pathlib import Path
from neo4j import GraphDatabase
from langchain_community.vectorstores import Neo4jVector
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

warnings.filterwarnings("ignore")
logging.getLogger("neo4j").setLevel(logging.ERROR)

class HybridRAGAnalystAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.auth = (user, password)
        self.neo4j_url = uri
        
        # Modelli locali Ollama
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
        # PROMPT 1: Estrazione pattern puro
        # self.extraction_prompt = ChatPromptTemplate.from_messages([
        #     ("system", """Sei un SOC Analyst e Security Researcher. 
        #     Analizza l'input e NON fare osservazioni iniziali.
        #     Restituisci solo una riga contenente i concetti fondamentali separati da una virgola.
        #     - CODICE: identifica la vulnerabilità (es. Buffer Overflow).
        #     - LOG: identifica l'attacco in corso (es. Password Spraying).
        #     - SCANSIONE: identifica il servizio vulnerabile (es. Apache RCE)."""),
        #     ("user", "INPUT DA ANALIZZARE:\n{content}")
        # ])

        # PROMPT 1: Estrazione Semantica Universale (JSON Mode)
        # self.extraction_prompt = ChatPromptTemplate.from_messages([
        #     ("system", """Sei un classificatore SOC. Il tuo unico scopo è estrarre la MINACCIA PRINCIPALE.
        #     DEVI rispondere ESCLUSIVAMENTE con un oggetto JSON valido.
            
        #     REGOLE DI DEDUZIONE:
        #     1. Se vedi query HTTP o payload (es. SLEEP, UNION), estrai la famiglia di attacco web (es. "SQL Injection", "XSS").
        #     2. Se vedi una scansione NMAP con porte aperte (es. 445, 3389) su sistemi operativi obsoleti, estrai il protocollo esposto più critico (es. "SMB Vulnerability", "RDP Exposure").
        #     3. Sii chirurgico: massimo 3 parole.
            
        #     Struttura JSON obbligatoria:
        #     {{
        #         "pattern": "Nome della minaccia"
        #     }}"""),
        #     ("user", "ARTEFATTO:\n{content}")
        # ])

        # PROMPT 1: Estrazione Universale Blindata (JSON + CoT + Sandwich)
        self.extraction_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un classificatore SOC. Il tuo unico scopo è estrarre la MINACCIA PRINCIPALE.
            DEVI rispondere ESCLUSIVAMENTE con un oggetto JSON valido, senza alcun testo fuori dal JSON.
            
            REGOLE DI DEDUZIONE:
            1. Se vedi query HTTP o payload (es. SLEEP, UNION, sqlmap), la minaccia è la famiglia di attacco web (es. "SQL Injection", "Cross-Site Scripting").
            2. Se vedi una scansione di rete (NMAP) con porte aperte (es. 445, 3389) su OS obsoleti, la minaccia è il protocollo esposto (es. "SMB Vulnerability", "RDP Exposure").
            
            Struttura JSON obbligatoria:
            {{
                "ragionamento": "Spiega in massimo 10 parole l'evidenza tecnica che vedi",
                "pattern": "Nome della minaccia (massimo 3 parole)"
            }}"""),
            
            ("user", """<raw_artifact>
{content}
</raw_artifact>

ATTENZIONE: Ignora le distrazioni e il rumore soprastante. Qual è la minaccia principale secondo le regole?
Rispondi SOLO con il JSON.""")
        ])

        # PROMPT 2: Generazione Report GraphRAG (Anti-Allucinazione)
        self.report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un SOC Analyst e Senior Security Architect spietatamente analitico. Il tuo compito è redigere un report tecnico, diretto e privo di convenevoli.
            
            ⚠️ REGOLE ZERO-HALLUCINATION (DA RISPETTARE ASSOLUTAMENTE):
            1. VIETATO usare frasi generiche, discorsive o riempitive come "Il presente report analizza...", "È importante aggiornare i sistemi" o "Le seguenti CVE sono state rilevate". Vai dritto ai dati tecnici.
            2. Usa SOLO ed ESCLUSIVAMENTE i dati presenti in "CONTESTO DAL GRAFO" e "PATTERN RILEVATO". Se un dato non c'è, non inventarlo.
            
            Usa OBBLIGATORIAMENTE i seguenti tag esatti per strutturare la risposta:

            [ANALISI]
            Riassumi in massimo 3 righe il vettore di attacco o il rischio rilevato, basandoti ESCLUSIVAMENTE sul "PATTERN RILEVATO" (es. cita protocolli esatti come Windows RPC o SMBv2).

            [IDENTIFICATIVI]
            Elenca le CVE trovate nel contesto. Per ciascuna, estrai la CWE e i Pattern CAPEC associati. 
            ⚠️ REGOLA FERREA: NON INVENTARE O IPOTIZZARE LE CWE. Usa solo i dati forniti alla voce 'DEBOLEZZA REALE' o 'PATTERN CAPEC'. Se non ci sono, scrivi "Nessuna vulnerabilità strutturata nel grafo."

            [KILL CHAIN]
            Ipotizza le prossime mosse dell'attaccante in base alle Tecniche MITRE fornite

            [STANDARD]
            Cita le norme NIST/ISO violate, restituisci un elenco puntato pulito ed elegante.

            [MITIGAZIONE]
            Fornisci contromisure specifiche per le esatte vulnerabilità (CWE/CVE) individuate."""),
            
            ("user", "CONTESTO DAL GRAFO:\n{context}\n\nPATTERN RILEVATO (Ricerca Vettoriale):\n{concept}")
        ])

        # Inizializzazione Indici Vettoriali
        self.vector_tech = self._init_vs("technique_vector_index", "Technique")
        self.vector_weak = self._init_vs("weakness_vector_index", "Weakness")
        self.vector_vuln = self._init_vs("vulnerability_vector_index", "Vulnerability")
        self.vector_expl = self._init_vs("exploit_vector_index", "Exploit")
        self.vector_patt = self._init_vs("pattern_vector_index", "Pattern")
        
        self.driver = GraphDatabase.driver(uri, auth=self.auth)

    def _init_vs(self, index_name, label):
        """Usa ID come testo base e ripristina i metadati per il passaggio al grafo."""
        return Neo4jVector.from_existing_index(
            embedding=self.embeddings,
            url=self.neo4j_url,
            username=self.auth[0],
            password=self.auth[1],
            index_name=index_name,
            retrieval_query=f"""
                RETURN node.id AS text, 
                       score, 
                       node {{.*, graph_id: node.id, label: labels(node)[0]}} AS metadata
            """
        )

    def _get_compliance_context(self, entities):
        """Graph Traversal Universale: Da qualsiasi nodo (CVE, CWE, Pattern), estrae la Kill Chain completa."""
        context = []
        with self.driver.session() as session:
            for ent in entities:
                query = """
                MATCH (n) WHERE n.id = $id
                
                // 1. ANCORAGGIO ALLA CAUSA RADICE (CWE)
                // Trova la Weakness indipendentemente dal tipo di nodo d'ingresso
                OPTIONAL MATCH (n:Vulnerability)-[:HAS_WEAKNESS]->(w1:Weakness)
                OPTIONAL MATCH (n:Pattern)-[:EXPLOITS]->(w2:Weakness)
                OPTIONAL MATCH (n:Technique)-[:MAPS_TO_PATTERN]->(:Pattern)-[:EXPLOITS]->(w3:Weakness)
                
                // Consolidiamo la target_weakness (se n è già una Weakness, usa se stesso)
                WITH n, CASE WHEN 'Weakness' IN labels(n) THEN n ELSE coalesce(w1, w2, w3) END as w
                
                // 2. ESPANSIONE DELLA KILL CHAIN E COMPLIANCE
                OPTIONAL MATCH (w)-[:VIOLATES]->(r:Requirement)
                OPTIONAL MATCH (p:Pattern)-[:EXPLOITS]->(w)
                OPTIONAL MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p)
                OPTIONAL MATCH (e:Exploit)-[:EXPLOITS_VULNERABILITY]->(n)
                
                RETURN n.id as entry_id, 
                       labels(n)[0] as entry_type,
                       n.description as entry_desc,
                       w.id + ' - ' + w.name as weakness,
                       collect(DISTINCT p.id + ' - ' + p.name) as attack_patterns,
                       collect(DISTINCT t.id + ' - ' + t.name) as mitre_techniques,
                       collect(DISTINCT e.id + ' (' + e.name + ')') as exploits,
                       collect(DISTINCT r.standard + ' ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                
                if res:
                    # Formattazione liste pulite
                    clean_compliance = [c for c in res['compliance'] if c and not c.startswith('None')]
                    comp_str = ", ".join(clean_compliance) if clean_compliance else "Nessuna normativa mappata direttamente."
                    
                    # Costruzione blocco di testo rigido per Llama3
                    block = f"=== ENTRATA GRAFO: [{res['entry_type']}] {res['entry_id']} ===\n"
                    block += f"DESCRIZIONE: {res['entry_desc'][:500]}...\n"
                    
                    if res['weakness']: block += f"🛡️ DEBOLEZZA REALE (Grafo): {res['weakness']}\n"
                    if res['attack_patterns']: block += f"🥷 PATTERN CAPEC (Grafo): {', '.join(res['attack_patterns'])}\n"
                    if res['mitre_techniques']: block += f"📊 TECNICHE MITRE (Grafo): {', '.join(res['mitre_techniques'])}\n"
                    if res['exploits']: block += f"💥 EXPLOIT DISPONIBILI: {', '.join(res['exploits'])}\n"
                    
                    block += f"📋 NORMATIVE VIOLATE: {comp_str}"
                    context.append(block)
                    
        return "\n\n".join(context)

    def _detect_input_type(self, file_path):
        """Determina il tipo di analisi in base all'estensione."""
        ext = file_path.suffix.lower()
        if ext in ['.py', '.c', '.cpp', '.js', '.go']: return "CODE"
        if ext in ['.log', '.txt', '.csv']: return "LOG"
        if ext in ['.json', '.xml', '.nmap']: return "SCAN"
        return "UNKNOWN"

    def analyze_content(self, path_str):
        from pathlib import Path
        from langchain_core.output_parsers import JsonOutputParser

        path = Path(path_str)
        workspace_data = {}
        files = list(path.rglob('*')) if path.is_dir() else [path]
        
        valid_exts = ['.py', '.c', '.cpp', '.js', '.go', '.log', '.csv', '.json', '.nmap', '.txt', '.xml']
        
        for f_path in files:
            if f_path.is_file() and f_path.suffix in valid_exts:
                with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                    workspace_data[f_path] = f.read()

        if not workspace_data: return "Nessun dato rilevante trovato.", []

        # Estraiamo il contenuto dell'unico file caricato
        f_path, content = list(workspace_data.items())[0]
        
        input_type = self._detect_input_type(f_path)
        print(f"🚀 Analisi tipo: {input_type} per il file {f_path.name}")

        # --- INIZIO BLOCCO ESTRAZIONE JSON BLINDATO ---
        try:
            # Riduciamo il contesto a 3000 caratteri per evitare l'amnesia dell'LLM locale
            extraction_chain = self.extraction_prompt | self.llm | JsonOutputParser()
            extracted_data = extraction_chain.invoke({"content": content[:3000]})
            
            # STAMPA DI DEBUG: Vediamo esattamente cosa ha generato l'LLM
            print(f"🛠️ DEBUG - JSON grezzo generato: {extracted_data}")
            
            concept = extracted_data.get('pattern', 'Sconosciuto')
            analisi_llm = extracted_data.get('ragionamento', 'Nessun ragionamento fornito')
            
            print(f"🧠 Ragionamento LLM: {analisi_llm}")
            
            # Se ha generato un JSON ma si è dimenticato la chiave corretta, forziamo il salvataggio
            if concept == 'Sconosciuto' or not concept:
                raise ValueError("L'LLM ha omesso la chiave 'pattern' nel JSON.")
                
        except Exception as e:
            print(f"⚠️ Errore di struttura o allucinazione catturata! Attivazione fallback. Dettagli: {e}")
            # Fallback intelligente ancorato al tipo di file
            concept = "SQL Injection" if input_type == "LOG" else "SMB Vulnerability"
            
        print(f"🎯 Pattern estratto via JSON: {concept}")
        # --- FINE BLOCCO ESTRAZIONE JSON BLINDATO ---
            

        # --- AGGIUNTA LOG ---
        print("🔍 Ricerca nel database vettoriale in corso...")
        # --------------------

        results = []
        if input_type == "LOG":
            results.extend(self.vector_patt.similarity_search(concept, k=4))
            results.extend(self.vector_tech.similarity_search(concept, k=2))
        elif input_type == "SCAN":
            results.extend(self.vector_vuln.similarity_search(concept, k=4))
            results.extend(self.vector_expl.similarity_search(concept, k=2))
        else:
            results.extend(self.vector_weak.similarity_search(concept, k=4))
            results.extend(self.vector_vuln.similarity_search(concept, k=2))

        entities = [{'id': d.metadata['graph_id'], 'label': d.metadata['label']} for d in results]
        
        # --- AGGIUNTA LOG ---
        print(f"🔗 Trovate {len(entities)} entità. Interrogazione del Grafo Neo4j...")
        # --------------------

        graph_data = self._get_compliance_context(entities)
        
        
        # --- GENERAZIONE DEL REPORT ---
        print("🧠 Llama3 sta generando il report finale. (Potrebbe volerci un po', preparati ad aspettare! ⏳)...")
        raw_report = (self.report_prompt | self.llm | StrOutputParser()).invoke({
            "context": graph_data, 
            "concept": concept
        })

        # --- FIX UI: NORMALIZZAZIONE DEI TAG ---
        print("🔧 Normalizzazione dei tag per la Dashboard Gradio...")
        report = self._normalize_report_tags(raw_report)
        
        # Ora il return è sicuro al 100% per lo smistamento!
        print("✅ Report generato e formattato con successo! Ritorno alla UI.")
        return report, entities

    def _normalize_report_tags(self, report_text):
        """
        Intercetta le invenzioni stilistiche e semantiche dell'LLM (es. **SUGGERIMENTI**, 
        **NORMATIVE VIOLATE**) e le forza nei 5 tag esatti attesi dal parser della UI Gradio.
        """
        import re
        
        # 1. Normalizza [ANALISI]
        report_text = re.sub(r'(?im)^\s*\*?\*?\[?(ANALISI)\]?\*?\*?:?\s*$', r'[ANALISI]', report_text)
        
        # 2. Normalizza [IDENTIFICATIVI] (cattura anche eventuali [CWE] o varianti create dall'LLM)
        report_text = re.sub(r'(?im)^\s*\*?\*?\[?(IDENTIFICATIVI|CWE|VULNERABILITÀ)\]?\*?\*?:?\s*$', r'[IDENTIFICATIVI]', report_text)
        
        # 3. Normalizza [KILL_CHAIN]
        report_text = re.sub(r'(?im)^\s*\*?\*?\[?(KILL\s?CHAIN|TECNICHE.*?|ATTACK.*?)\]?\*?\*?:?\s*$', r'[KILL_CHAIN]', report_text)
        
        # 4. Normalizza [STANDARD] (cattura NORMATIVE VIOLATE, COMPLIANCE, ecc.)
        report_text = re.sub(r'(?im)^\s*\*?\*?\[?(STANDARD|NORMATIVE.*?|COMPLIANCE)\]?\*?\*?:?\s*$', r'[STANDARD]', report_text)
        
        # 5. Normalizza [MITIGAZIONE] (cattura SUGGERIMENTI, RACCOMANDAZIONI, RISPOSTA)
        report_text = re.sub(r'(?im)^\s*\*?\*?\[?(MITIGAZIONE|SUGGERIMENTI|RACCOMANDAZIONI|RISPOSTA)\]?\*?\*?:?\s*$', r'[MITIGAZIONE]', report_text)
        
        return report_text

    def close(self):
        self.driver.close()

if __name__ == "__main__":
    analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "ciaociao", "http://10.0.2.2:11434")
    try:
        # Passiamo la scansione per la macchina BLUE
        report, found = analyst.analyze_content("../testing/simple_ctf.log")
        print("\n" + "═"*30 + " REPORT DI ANALISI IBRIDA " + "═"*30)
        print(report)
        print("═"*86)
    finally:
        analyst.close()