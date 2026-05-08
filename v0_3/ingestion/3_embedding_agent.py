from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings
import time

class VectorialistAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        # Utilizziamo nomic-embed-text per la sua efficienza in ambito tecnico
        self.embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=ollama_url)

    def close(self):
        self.driver.close()

    def generate_embeddings(self, label):
        """Genera vettori solo per i nodi che ne sono sprovvisti."""
        print(f"🔄 Agente Vectorialist: Generazione vettori per {label}...")
        with self.driver.session() as session:
            query = f"MATCH (n:{label}) WHERE n.embedding IS NULL AND n.description IS NOT NULL RETURN n.id as id, n.description as desc"
            nodes = session.run(query).data()
            
            if not nodes:
                print(f"   -> ✅ Tutti i nodi {label} sono già vettorizzati.")
                return

            print(f"   -> Elaborazione di {len(nodes)} nodi in corso...")
            for i, node in enumerate(nodes):
                vector = self.embeddings.embed_query(node['desc'])
                session.run(f"MATCH (n:{label} {{id: $id}}) SET n.embedding = $vec", id=node['id'], vec=vector)
                
                if (i + 1) % 50 == 0:
                    print(f"   -> Progresso {label}: {i + 1}/{len(nodes)}")

    def create_indices(self):
        """Attiva gli indici per la ricerca semantica."""
        print("🏗️ Agente Vectorialist: Configurazione indici vettoriali...")
        with self.driver.session() as session:
            # Indice per le Tecniche MITRE
            session.run("""
                CREATE VECTOR INDEX `cyber_vector_index` IF NOT EXISTS
                FOR (n:Technique) ON (n.embedding)
                OPTIONS {indexConfig: {
                 `vector.dimensions`: 768,
                 `vector.similarity_function`: 'cosine'
                }}
            """)
            # Indice per le Debolezze CWE
            session.run("""
                CREATE VECTOR INDEX `weakness_vector_index` IF NOT EXISTS
                FOR (n:Weakness) ON (n.embedding)
                OPTIONS {indexConfig: {
                 `vector.dimensions`: 768,
                 `vector.similarity_function`: 'cosine'
                }}
            """)
        print("   -> Indici Technique e Weakness pronti.")

    def verify(self):
        print("\n🔎 --- VERIFICA VETTORIALE ---")
        with self.driver.session() as session:
            res_t = session.run("MATCH (n:Technique) WHERE n.embedding IS NOT NULL RETURN count(n) as c").single()
            res_w = session.run("MATCH (n:Weakness) WHERE n.embedding IS NOT NULL RETURN count(n) as c").single()
            print(f"Tecniche vettorizzate: {res_t['c']}")
            print(f"Weakness vettorizzate: {res_w['c']}")

if __name__ == "__main__":
    URI = "bolt://10.0.2.2:7687"
    OLLAMA_URL = "http://10.0.2.2:11434"
    agent = VectorialistAgent(URI, "neo4j", "***REMOVED***", OLLAMA_URL)
    try:
        agent.generate_embeddings("Technique")
        agent.generate_embeddings("Weakness")
        agent.create_indices()
        agent.verify()
    finally:
        agent.close()