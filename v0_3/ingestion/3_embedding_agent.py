from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings
import time

class VectorialistAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)

    def close(self):
        self.driver.close()

    def generate_embeddings(self, label, force_update=False):
        print(f"🔄 Agente Vectorialist: Generazione vettori per {label}...")
        
        with self.driver.session() as session:
            if force_update:
                session.run(f"MATCH (n:{label}) SET n.embedding = null")
                # Recuperiamo anche il nome per dare più contesto al vettore
                query = f"MATCH (n:{label}) WHERE n.description IS NOT NULL RETURN n.id as id, n.name as name, n.description as desc"
            else:
                query = f"MATCH (n:{label}) WHERE n.embedding IS NULL AND n.description IS NOT NULL RETURN n.id as id, n.name as name, n.description as desc"
            
            nodes = session.run(query).data()
            if not nodes: return

            for i, node in enumerate(nodes):
                try:
                    # COSTRUZIONE TESTO ESSENZIALE: Nome + primi 1000 caratteri
                    # Questo garantisce che il 'concetto' sia salvo senza sforare i token
                    safe_text = f"Technique: {node['name']}. Description: {node['desc'][:1000]}"
                    
                    vector = self.embeddings.embed_query(safe_text)
                    session.run(f"MATCH (n:{label} {{id: $id}}) SET n.embedding = $vec", 
                                id=node['id'], vec=vector)
                except Exception as e:
                    # Se fallisce ancora, proviamo solo con il nome (fallback estremo)
                    try:
                        vector = self.embeddings.embed_query(node['name'])
                        session.run(f"MATCH (n:{label} {{id: $id}}) SET n.embedding = $vec", 
                                    id=node['id'], vec=vector)
                    except:
                        print(f"   ❌ Errore critico irrisolvibile su {node['id']}")

    def create_indices(self):
        """Ricrea gli indici per la nuova dimensione 1024."""
        print("🏗️ Configurazione indici vettoriali (1024 dimensioni)...")
        with self.driver.session() as session:
            session.run("DROP INDEX weakness_vector_index IF EXISTS")
            session.run("DROP INDEX cyber_vector_index IF EXISTS")
            
            session.run("""
                CREATE VECTOR INDEX `cyber_vector_index` IF NOT EXISTS
                FOR (n:Technique) ON (n.embedding)
                OPTIONS {indexConfig: {`vector.dimensions`: 1024, `vector.similarity_function`: 'cosine'}}
            """)
            session.run("""
                CREATE VECTOR INDEX `weakness_vector_index` IF NOT EXISTS
                FOR (n:Weakness) ON (n.embedding)
                OPTIONS {indexConfig: {`vector.dimensions`: 1024, `vector.similarity_function`: 'cosine'}}
            """)
        print("   -> Indici pronti.")

if __name__ == "__main__":
    URI, OLLAMA_URL = "bolt://10.0.2.2:7687", "http://10.0.2.2:11434"
    agent = VectorialistAgent(URI, "neo4j", "ciaociao", OLLAMA_URL)
    try:
        agent.generate_embeddings("Technique", force_update=True)
        agent.generate_embeddings("Weakness", force_update=True)
        agent.create_indices()
        print("\n✨ Operazione completata con successo!")
    finally:
        agent.close()