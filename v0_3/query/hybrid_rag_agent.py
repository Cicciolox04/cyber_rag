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
        self.extraction_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un SOC Analyst e Security Researcher. 
            Analizza l'input ed estrai il 'Security Pattern' principale.
            Restituisci UNICAMENTE una lista di parole chiave separate da virgola, senza alcun preambolo.
            - CODICE: identifica la vulnerabilità (es. Buffer Overflow).
            - LOG: identifica l'attacco in corso (es. Password Spraying).
            - SCANSIONE: identifica il servizio vulnerabile (es. Apache RCE)."""),
            ("user", "INPUT DA ANALIZZARE:\n{content}")
        ])

        # PROMPT 2: Generazione Report GraphRAG (Anti-Allucinazione)
        self.report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Senior Security Architect. Genera un report professionale in ITALIANO.
            Usa OBBLIGATORIAMENTE questi tag:

            [ANALISI]
            (Descrivi cosa è stato rilevato)

            [IDENTIFICATIVI]
            (Elenca le CVE trovate nel contesto. Per ciascuna CVE, DEVI estrarre e trascrivere la CWE e i Pattern CAPEC associati riportati nel 'CONTESTO DAL GRAFO'. 
            ⚠️ REGOLA FERREA: NON INVENTARE O IPOTIZZARE LE CWE. Usa solo ed esclusivamente i dati strutturati forniti alla voce 'DEBOLEZZA REALE' o 'PATTERN CAPEC'.)

            [KILL CHAIN]
            (Ipotizza le prossime mosse dell'attaccante in base alle Tecniche MITRE fornite)

            [STANDARD]
            (Cita le norme NIST/ISO violate, riportate alla voce 'NORMATIVE VIOLATE')

            [MITIGAZIONE]
            (Suggerisci correzioni in base alla causa radice)"""),
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
        path = Path(path_str)
        workspace_data = {}
        files = list(path.rglob('*')) if path.is_dir() else [path]
        
        valid_exts = ['.py', '.c', '.cpp', '.js', '.go', '.log', '.csv', '.json', '.nmap', '.txt', '.xml']
        
        for f_path in files:
            if f_path.is_file() and f_path.suffix in valid_exts:
                with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                    workspace_data[f_path] = f.read()

        if not workspace_data: return "Nessun dato rilevante trovato.", []

        for f_path, content in workspace_data.items():
            input_type = self._detect_input_type(f_path)
            print(f"🚀 Analisi tipo: {input_type} per il file {f_path.name}")

            concept = (self.extraction_prompt | self.llm | StrOutputParser()).invoke({"content": content[:8000]})
            print(f"🎯 Pattern estratto: {concept[:100]}...")

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
            
            graph_data = self._get_compliance_context(entities)
            report = (self.report_prompt | self.llm | StrOutputParser()).invoke({
                "context": graph_data, 
                "concept": concept
            })
            
            return report, entities

    def close(self):
        self.driver.close()

if __name__ == "__main__":
    analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "ciaociao", "http://10.0.2.2:11434")
    try:
        # Passiamo la scansione per la macchina BLUE
        report, found = analyst.analyze_content("../testing/test3/vulnerable_app.py")
        print("\n" + "═"*30 + " REPORT DI ANALISI IBRIDA " + "═"*30)
        print(report)
        print("═"*86)
    finally:
        analyst.close()