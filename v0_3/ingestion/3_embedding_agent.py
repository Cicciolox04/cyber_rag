from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings
import time

class VectorialistAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        # Utilizziamo il modello mxbai-embed-large per la sua ottima capacità di comprensione tecnica
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)

    def close(self):
        self.driver.close()

    def generate_embeddings(self, label, force_update=False, limit=None):
        """
        Genera embeddings per un'etichetta specifica. 
        Supporta il campionamento tramite il parametro 'limit'.
        """
        print(f"🔄 Agente Vectorialist: Generazione vettori per {label} (Limite: {limit if limit else 'Nessuno'})...")
        
        with self.driver.session() as session:
            if force_update:
                session.run(f"MATCH (n:{label}) SET n.embedding = null")
            
            # Clausola opzionale per limitare il numero di nodi da processare
            limit_clause = f"LIMIT {limit}" if limit else ""
            
            # Query definitiva con ordinamento prioritario per la tesi
            query = f"""
            MATCH (n:{label}) 
            WHERE n.embedding IS NULL AND n.description IS NOT NULL 
            
            // Filtro sugli anni utili per i tuoi laboratori THM
            AND (
                NOT '{label}' = 'Vulnerability' 
                OR n.id STARTS WITH 'CVE-2017' 
                OR n.id STARTS WITH 'CVE-2019'
                OR n.id STARTS WITH 'CVE-2021' 
                OR n.id STARTS WITH 'CVE-2024'
                OR n.id STARTS WITH 'CVE-2025'
            )
            
            RETURN n.id as id, 
                   n.name as name, 
                   n.description as desc,
                   n.platform as platform,
                   n.type as type
            
            // FORZIAMO LA PRECEDENZA ASSOLUTA PER LE TUE MACCHINE DI TEST
            ORDER BY 
              CASE 
                WHEN n.id = 'CVE-2017-0144' THEN 0  // EternalBlue (Stanza Blue)
                WHEN n.id = 'CVE-2019-9053' THEN 0  // SQLi (Stanza Kenobi)
                WHEN n.id STARTS WITH 'CVE-2017' THEN 1
                WHEN n.id STARTS WITH 'CVE-2019' THEN 1
                WHEN n.id STARTS WITH 'CVE-2021' THEN 2
                ELSE 3 
              END ASC
            {limit_clause}
            """
            
            nodes = session.run(query).data()
            if not nodes:
                print(f"   ℹ️ Nessun nuovo nodo '{label}' da indicizzare.")
                return

            print(f"   -> Elaborazione di un campione di {len(nodes)} nodi...")
            for i, node in enumerate(nodes):
                try:
                    # COSTRUZIONE DEL TESTO SEMANTICO (Contextual Prompting)
                    if label == "Pattern":
                        # Per le CAPEC includiamo il nome e la descrizione per catturare il comportamento
                        safe_text = f"Attack Pattern: {node.get('name', '')}. Description: {node['desc'][:1200]}"
                    elif label == "Exploit":
                        safe_text = f"Exploit: {node['desc']}. Platform: {node.get('platform', 'N/A')}. Type: {node.get('type', 'N/A')}"
                    elif label == "Vulnerability":
                        safe_text = f"Vulnerability {node['id']}: {node['desc'][:1200]}"
                    else:
                        name_str = node.get('name', node['id'])
                        safe_text = f"{label}: {name_str}. Description: {node['desc'][:1000]}"
                    
                    vector = self.embeddings.embed_query(safe_text)
                    session.run(f"MATCH (n:{label} {{id: $id}}) SET n.embedding = $vec", 
                                id=node['id'], vec=vector)
                    
                    if (i + 1) % 100 == 0:
                        print(f"      - Progressi: {i + 1}/{len(nodes)}...")
                        
                except Exception as e:
                    print(f"   ⚠️ Errore su {node['id']}: {e}")
                    continue

    def create_indices(self):
        """Crea o ricrea gli indici vettoriali su Neo4j."""
        print("🏗️ Configurazione indici vettoriali (1024 dimensioni)...")
        with self.driver.session() as session:
            indices = [
                ("technique_vector_index", "Technique"),
                ("weakness_vector_index", "Weakness"),
                ("vulnerability_vector_index", "Vulnerability"),
                ("exploit_vector_index", "Exploit"),
                ("pattern_vector_index", "Pattern") # NUOVO INDICE
            ]
            
            for index_name, label in indices:
                session.run(f"""
                    CREATE VECTOR INDEX `{index_name}` IF NOT EXISTS
                    FOR (n:{label}) ON (n.embedding)
                    OPTIONS {{indexConfig: {{
                        `vector.dimensions`: 1024, 
                        `vector.similarity_function`: 'cosine'
                    }}}}
                """)
        print("   -> Tutti gli indici sono pronti.")

if __name__ == "__main__":
    URI, OLLAMA_URL = "bolt://10.0.2.2:7687", "http://10.0.2.2:11434"
    
    agent = VectorialistAgent(URI, "neo4j", "ciaociao", OLLAMA_URL)
    try:
        # Applichiamo un limite didattico alle etichette più popolose
        agent.generate_embeddings("Vulnerability", force_update=False, limit=1000)
        agent.generate_embeddings("Exploit", force_update=False, limit=1000)
        
        # Per Technique e Weakness possiamo indicizzare tutto (volumi ridotti)
        agent.generate_embeddings("Technique", force_update=False)
        agent.generate_embeddings("Weakness", force_update=False)

        agent.generate_embeddings("Pattern", force_update=False)
        
        # Creazione indici
        agent.create_indices()
        
        print("\n✨ Operazione completata! Grafo pronto per HybridRAGAgent.")
    finally:
        agent.close()