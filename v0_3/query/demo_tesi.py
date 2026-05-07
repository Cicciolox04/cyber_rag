import os
import warnings
from neo4j import GraphDatabase
from langchain_community.vectorstores import Neo4jVector
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# Silenziamo i warning di deprecazione per un output pulito nella tesi
warnings.filterwarnings("ignore", category=UserWarning, message=".*db.index.vector.queryNodes.*")

class MasterHybridRAG:
    def __init__(self):
        self.url = "http://10.0.2.2:11434"
        self.neo4j_url = "bolt://10.0.2.2:7687"
        self.auth = ("neo4j", "ciaociao")
        
        # PASSO 3: Per migliorare la logica, usiamo un modello di embedding 
        # che lavora bene con concetti tecnici (nomic-embed-text)
        self.embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=self.url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=self.url)
        
        # Configurazione Vector Stores (Tecniche e Debolezze)
        self.vector_tech = Neo4jVector.from_existing_graph(
            embedding=self.embeddings,
            url=self.neo4j_url, username=self.auth[0], password=self.auth[1],
            index_name="cyber_vector_index",
            node_label="Technique",
            text_node_properties=["description"],
            embedding_node_property="embedding",
            retrieval_query="RETURN node.description AS text, score, node {.*, graph_id: node.id, label: 'Technique'} AS metadata"
        )
        
        self.vector_weak = Neo4jVector.from_existing_graph(
            embedding=self.embeddings,
            url=self.neo4j_url, username=self.auth[0], password=self.auth[1],
            index_name="weakness_vector_index",
            node_label="Weakness",
            text_node_properties=["description"],
            embedding_node_property="embedding",
            retrieval_query="RETURN node.description AS text, score, node {.*, graph_id: node.id, label: 'Weakness'} AS metadata"
        )
        
        self.driver = GraphDatabase.driver(
            self.neo4j_url, 
            auth=self.auth,
            notifications_min_severity="OFF" # Nasconde i messaggi di sistema
        )

    def close(self):
        """Chiude correttamente la connessione al database."""
        if hasattr(self, 'driver'):
            self.driver.close()
            print("\n🔌 Sessione Neo4j terminata correttamente.")

    def _summarize_vulnerability_semantics(self, code):
        """Analisi concettuale per migliorare la precisione del Vector Search."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """Analizza il codice e descrivi la vulnerabilità principale in una frase breve (10-15 parole). 
            NON citare ID (CWE-xxx o Txxx)."""),
            ("user", "CODICE:\n{code}")
        ])
        chain = prompt | self.llm | StrOutputParser()
        summary = chain.invoke({"code": code[:2000]})
        print(f"🎯 Concetto identificato: {summary}")
        return summary

    def _get_deep_context(self, entities):
        """Naviga nei 395 ponti di compliance del grafo"""
        context = []
        with self.driver.session() as session:
            for ent in entities:
                query = """
                MATCH (n) WHERE n.id = $id
                OPTIONAL MATCH (n)-[:HAS_WEAKNESS|VIOLATES|INFERRED_COMPLIANCE*1..2]->(r:Requirement)
                RETURN n.id as id, n.name as name, labels(n)[0] as type,
                       collect(DISTINCT r.standard + ' Sez. ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                if res:
                    info = f"\n[MATCH {res['type']}: {res['id']} - {res['name']}]\n"
                    info += f"Ponti Compliance attivati: {res['compliance']}\n"
                    context.append(info)
        return "\n".join(context)

    def analyze(self, file_path):
        print(f"🔍 Avvio Analisi Avanzata su: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()

        # FASE 1: L'LLM estrae il concetto (Passo 2)
        search_query = self._summarize_vulnerability_semantics(code)

        # FASE 2: Cerchiamo il concetto nel Grafo invece del codice grezzo
        docs_t = self.vector_tech.similarity_search(search_query, k=2)
        docs_w = self.vector_weak.similarity_search(search_query, k=2)
        
        found_entities = [{'id': d.metadata['graph_id'], 'type': d.metadata['label']} 
                          for d in docs_t + docs_w if 'graph_id' in d.metadata]
        
        # FASE 3: Esplorazione dei ponti logici
        context = self._get_deep_context(found_entities)

        # FASE 4: Report Finale
        prompt = ChatPromptTemplate.from_messages([
            ("system", "Sei un Senior Security Architect. Rispondi in ITALIANO. Usa i dati del grafo per mappare le violazioni ISO/NIST. Sii estremamente tecnico."),
            ("user", "CODICE SORGENTE:\n{code}\n\nDATI ESTRATTI DAL GRAFO:\n{context}")
        ])
        
        chain = prompt | self.llm | StrOutputParser()
        return chain.invoke({"code": code, "context": context}), found_entities

if __name__ == "__main__":
    rag = MasterHybridRAG()
    try:
        target_file = "../testing/vulnerable.c"
        report, entities = rag.analyze(target_file)
        
        print("\n" + "="*20 + " ENTITÀ RILEVATE (AUGMENTED) " + "="*20)
        for ent in entities:
            print(f"- [{ent['type']}] {ent['id']}")
        
        print("\n" + "="*30 + " REPORT FINALE " + "="*30)
        print(report)
    finally:
        rag.close()