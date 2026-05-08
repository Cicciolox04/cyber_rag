import warnings
from neo4j import GraphDatabase
from langchain_community.vectorstores import Neo4jVector
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import logging

# Silenziamo i warning per un output pulito nella presentazione della tesi
warnings.filterwarnings("ignore", category=UserWarning, message=".*db.index.vector.queryNodes.*")

# Disabilita il logging del driver Neo4j che stampa le notifiche del DBMS
logging.getLogger("neo4j").setLevel(logging.ERROR)

class HybridRAGAnalystAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.auth = (user, password)
        self.neo4j_url = uri
        self.ollama_url = ollama_url
        
        # Modelli
        self.embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
        # Connessione ai due indici vettoriali (MITRE e CWE)
        self.vector_tech = self._init_vector_store("cyber_vector_index", "Technique")
        self.vector_weak = self._init_vector_store("weakness_vector_index", "Weakness")
        
        self.driver = GraphDatabase.driver(uri, auth=self.auth, notifications_min_severity="OFF")

    def _init_vector_store(self, index_name, label):
        return Neo4jVector.from_existing_graph(
            embedding=self.embeddings,
            url=self.neo4j_url, username=self.auth[0], password=self.auth[1],
            index_name=index_name,
            node_label=label,
            text_node_properties=["description"],
            embedding_node_property="embedding",
            retrieval_query="RETURN node.description AS text, score, node {.*, graph_id: node.id, label: labels(node)[0]} AS metadata"
        )

    def close(self):
        self.driver.close()

    def _extract_vulnerability_concept(self, code):
        """Analisi concettuale del codice (Passo 2 del piano agentico)."""
        print("🧠 Analisi concettuale del codice in corso...")
        prompt = ChatPromptTemplate.from_messages([
            ("system", "Sei un esperto di cybersecurity. Descrivi la vulnerabilità nel codice in una frase senza usare ID."),
            ("user", "CODICE:\n{code}")
        ])
        chain = prompt | self.llm | StrOutputParser()
        return chain.invoke({"code": code})

    def _get_compliance_context(self, entities):
        """Navigazione dei 395 ponti di compliance."""
        context = []
        with self.driver.session() as session:
            for ent in entities:
                query = """
                MATCH (n) WHERE n.id = $id
                OPTIONAL MATCH (n)-[:HAS_WEAKNESS|VIOLATES|INFERRED_COMPLIANCE*1..2]->(r:Requirement)
                RETURN n.id as id, n.name as name, labels(n)[0] as type,
                       collect(DISTINCT r.standard + ' ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                if res:
                    info = f"\n[Rilevato {res['type']}: {res['id']} - {res['name']}]\n"
                    info += f"Ponti Compliance: {res['compliance']}\n"
                    context.append(info)
        return "\n".join(context)

    def analyze_content(self, file_path):
        print(f"🔍 Analisi Ibrida Avanzata: {file_path}")
        with open(file_path, 'r') as f:
            code = f.read()

        # 1. Estrazione del concetto
        concept = self._extract_vulnerability_concept(code)
        print(f"🎯 Concetto rilevato: {concept}")

        # 2. Ricerca nel grafo (MITRE + CWE)
        docs = self.vector_tech.similarity_search(concept, k=2) + self.vector_weak.similarity_search(concept, k=2)
        entities = [{'id': d.metadata['graph_id'], 'label': d.metadata['label']} for d in docs]
        
        # 3. Recupero Compliance
        graph_data = self._get_compliance_context(entities)

        # FASE 4: Report Finale (Prompt potenziato)
        report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Senior Security Architect. Rispondi in ITALIANO.
            
            REGOLE RIGIDE:
            1. Usa i dati del grafo per citare ESPLICITAMENTE i controlli ISO/NIST (es. 'Violazione NIST SI-16').
            2. Se il grafo riporta una sezione specifica (es. Sez. 12.4.1), devi includerla.
            3. Non essere generico: se il grafo dice che CWE-77 viola AC-2, scrivi 'La CWE-77 comporta una violazione del controllo NIST AC-2'.
            """),
            ("user", "CODICE SORGENTE:\n{code}\n\nDATI ESTRATTI DAL GRAFO:\n{context}")
        ])
        chain = report_prompt | self.llm | StrOutputParser()
        return chain.invoke({"code": code, "context": graph_data}), entities

if __name__ == "__main__":
    analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "***REMOVED***", "http://10.0.2.2:11434")
    try:
        # Esegui il test su uno dei tuoi file
        report, found = analyst.analyze_content("../testing/cmd_injection.c")
        print("\n" + "="*20 + " RISULTATI DEL GRAFO " + "="*20)
        for f in found: print(f"- [{f['label']}] {f['id']}")
        print("\n" + "="*20 + " REPORT FINALE " + "="*20)
        print(report)
    finally:
        analyst.close()