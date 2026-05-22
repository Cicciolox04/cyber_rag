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
        # Utilizziamo lo stesso modello di embedding usato per l'indicizzazione
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
        # PROMPT EVOLUTO: Ora estrae pattern indipendentemente dall'input
        self.extraction_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un esperto SOC Analyst e Security Researcher. 
            Analizza l'input (Codice, Log o Scansione) ed estrai il 'Security Pattern' principale.
            
            Genera poche parole chiave che rappresentano il PATTERN RILEVATO.

            - Se è CODICE: identifica la vulnerabilità (es. Buffer Overflow).
            - Se è un LOG: identifica l'attacco in corso (es. Password Spraying).
            - Se è una SCANSIONE: identifica il servizio vulnerabile o la CVE (es. Apache RCE)."""),
            ("user", "INPUT DA ANALIZZARE:\n{content}")
        ])

        self.report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Senior Security Architect. Genera un report professionale in ITALIANO.
            Usa OBBLIGATORIAMENTE questi tag:

            [ANALISI]
            (Descrivi cosa è stato rilevato: vulnerabilità nel codice, attacco nei log o falla nella rete)

            [IDENTIFICATIVI]
            (Elenca CVE, CWE, CAPEC e Tecniche MITRE correlate)

            [KILL CHAIN]
            (Ipotizza quali saranno le prossime mosse dell'attaccante: come verrà sfruttata la vulnerabilità trovata?)

            [STANDARD]
            (Cita le norme NIST 800-53 o ISO 27001 violate)

            [MITIGAZIONE]
            (Suggerisci correzioni al codice o modifiche alla configurazione di rete/firewall)"""),
            ("user", "CONTESTO DAL GRAFO:\n{context}\n\nPATTERN RILEVATO:\n{concept}")
        ])

        # Inizializzazione dei magazzini vettoriali con protezione per descrizioni lunghe
        self.vector_tech = self._init_vs("technique_vector_index", "Technique")
        self.vector_weak = self._init_vs("weakness_vector_index", "Weakness")
        self.vector_vuln = self._init_vs("vulnerability_vector_index", "Vulnerability")
        self.vector_expl = self._init_vs("exploit_vector_index", "Exploit")
        
        # AGGIUNTA: Pattern Index per i Log
        self.vector_patt = self._init_vs("pattern_vector_index", "Pattern")
        
        self.driver = GraphDatabase.driver(uri, auth=self.auth)

    def _init_vs(self, index_name, label):
        """
        Versione ottimizzata: usa ID come testo base e ripristina i metadati 
        necessari per evitare KeyError.
        """
        return Neo4jVector.from_existing_index(
            embedding=self.embeddings,
            url=self.neo4j_url,
            username=self.auth[0],
            password=self.auth[1],
            index_name=index_name,
            # Passiamo la retrieval query per mantenere la tua struttura di metadati custom
            retrieval_query=f"""
                RETURN node.id AS text, 
                       score, 
                       node {{.*, graph_id: node.id, label: labels(node)[0]}} AS metadata
            """
        )

    def _get_compliance_context(self, entities):
        """Attraversa il grafo per trovare i percorsi dai dati tecnici alla compliance."""
        context = []
        with self.driver.session() as session:
            for ent in entities:
                # Navigazione fino a 3 salti (CVE -> CWE -> Requirement)
                query = """
                MATCH (n) WHERE n.id = $id
                OPTIONAL MATCH (n)-[:INSTANCE_OF|EXPLOITS_VULNERABILITY|DIRECTLY_THREATENS|VIOLATES|HAS_WEAKNESS*1..3]->(r:Requirement)
                RETURN n.id as id, n.name as name, labels(n)[0] as type, n.description as desc, n.file_path as path,
                       collect(DISTINCT r.standard + ' ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                if res:
                    comp = ", ".join(res['compliance']) if res['compliance'] else "Nessun requisito mappato direttamente"
                    name_str = res['name'] if res['name'] else "N/A"
                    path_info = f"\nFILE EXPLOIT: {res['path']}" if res.get('path') else ""
                    context.append(f"🔍 [{res['type']}] {res['id']} ({name_str})\nDEF: {res['desc'][:500]}{path_info}\nNORME: {comp}")
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
        
        # Filtro estensioni ampliato
        valid_exts = ['.py', '.c', '.cpp', '.js', '.log', '.json', '.nmap', '.txt']
        
        for f_path in files:
            if f_path.is_file() and f_path.suffix in valid_exts:
                with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                    workspace_data[f_path] = f.read()

        if not workspace_data: return "Nessun dato rilevante trovato.", []

        # Elaborazione differenziata
        for f_path, content in workspace_data.items():
            input_type = self._detect_input_type(f_path)
            print(f"🚀 Analisi tipo: {input_type} per il file {f_path.name}")

            # Estrazione del concetto (Pattern)
            concept = (self.extraction_prompt | self.llm | StrOutputParser()).invoke({"content": content[:8000]})
            print(f"🎯 Pattern estratto: {concept[:100]}...")

            # STRATEGIA DI RICERCA IBRIDA DIFFERENZIATA
            results = []
            if input_type == "LOG":
                # Nei log cerchiamo prima i PATTERN (CAPEC) e le TECNICHE (MITRE)
                results.extend(self.vector_patt.similarity_search(concept, k=4))
                results.extend(self.vector_tech.similarity_search(concept, k=2))
            elif input_type == "SCAN":
                # Nelle scansioni cerchiamo CVE (Vulnerability) ed EXPLOIT
                results.extend(self.vector_vuln.similarity_search(concept, k=4))
                results.extend(self.vector_expl.similarity_search(concept, k=2))
            else:
                # Codice statico: focus su CWE (Weakness)
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
        # Percorso del file da testare (es. hardcoded_creds.py)
        report, found = analyst.analyze_content("../testing/vulnerable.c")
        print("\n" + "═"*30 + " REPORT DI ANALISI IBRIDA " + "═"*30)
        print(report)
        print("═"*86)
    finally:
        analyst.close()