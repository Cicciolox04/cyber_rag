from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings
import time

# --- CONFIGURAZIONE ---
URI = "bolt://10.0.2.2:7687"
AUTH = ("neo4j", "ciaociao")
OLLAMA_BASE_URL = "http://10.0.2.2:11434"
MODEL_NAME = "nomic-embed-text" 
DIMENSIONS = 768

class Neo4jVectorSetup:
    def __init__(self):
        self.driver = GraphDatabase.driver(URI, auth=AUTH)
        self.embeddings = OllamaEmbeddings(model=MODEL_NAME, base_url=OLLAMA_BASE_URL)

    def close(self):
        self.driver.close()

    def phase_1_safe_generate(self, label):
        """Genera embedding SOLO per i nodi che ne sono sprovvisti."""
        print(f"🔍 Controllo nodi {label}...")
        with self.driver.session() as session:
            # Cerchiamo solo chi non ha l'embedding
            query_get = f"""
                MATCH (n:{label}) 
                WHERE n.embedding IS NULL AND n.description IS NOT NULL 
                RETURN n.id as id, n.description as desc
            """
            nodes = session.run(query_get).data()
            
            if not nodes:
                print(f"✅ Salto {label}: tutti i nodi hanno già un embedding o non hanno descrizione.")
                return

            print(f"🔄 [Fase 1] Trovati {len(nodes)} nodi {label} da elaborare (gli altri verranno preservati).")
            for i, node in enumerate(nodes):
                vector = self.embeddings.embed_query(node['desc'])
                query_set = f"MATCH (n:{label} {{id: $id}}) SET n.embedding = $vec"
                session.run(query_set, id=node['id'], vec=vector)
                
                if (i + 1) % 50 == 0:
                    print(f"   -> Avanzamento {label}: {i + 1}/{len(nodes)}")

    def phase_2_setup_indices(self):
        """Configura gli indici vettoriali senza distruggere i dati."""
        print(f"🏗️ [Fase 2] Configurazione Indici Vettoriali...")
        with self.driver.session() as session:
            # Indice Tecniche (823 nodi)
            session.run("""
                CREATE VECTOR INDEX `cyber_vector_index` IF NOT EXISTS
                FOR (n:Technique) ON (n.embedding)
                OPTIONS {indexConfig: {
                 `vector.dimensions`: 768,
                 `vector.similarity_function`: 'cosine'
                }}
            """)
            
            # Indice Debolezze (587 nodi)
            session.run("""
                CREATE VECTOR INDEX `weakness_vector_index` IF NOT EXISTS
                FOR (n:Weakness) ON (n.embedding)
                OPTIONS {indexConfig: {
                 `vector.dimensions`: 768,
                 `vector.similarity_function`: 'cosine'
                }}
            """)
            print("   -> Indici Technique e Weakness pronti.")
            time.sleep(2)

if __name__ == "__main__":
    setup = Neo4jVectorSetup()
    try:
        # Gestione sicura per le 823 tecniche e 587 vulnerabilità
        setup.phase_1_safe_generate("Technique")
        setup.phase_1_safe_generate("Weakness")
        setup.phase_2_setup_indices()
        print("\n✨ Database aggiornato. I vecchi embedding sono stati preservati.")
    finally:
        setup.close()