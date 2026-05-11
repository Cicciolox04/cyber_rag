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

    def generate_embeddings(self, label, force_update=False):
        """
        Genera embeddings per un'etichetta specifica. 
        Supporta Technique, Weakness, Vulnerability ed Exploit.
        """
        print(f"🔄 Agente Vectorialist: Generazione vettori per {label}...")
        
        with self.driver.session() as session:
            if force_update:
                session.run(f"MATCH (n:{label}) SET n.embedding = null")
            
            # Recuperiamo i nodi che hanno una descrizione ma non ancora un embedding
            # Per gli Exploit prendiamo anche platform e type per arricchire il contesto
            query = f"""
            MATCH (n:{label}) 
            WHERE n.embedding IS NULL AND n.description IS NOT NULL 
            RETURN n.id as id, 
                   n.name as name, 
                   n.description as desc,
                   n.platform as platform,
                   n.type as type
            """
            
            nodes = session.run(query).data()
            if not nodes:
                print(f"   ℹ️ Nessun nuovo nodo '{label}' da indicizzare.")
                return

            print(f"   -> Elaborazione di {len(nodes)} nodi...")
            for i, node in enumerate(nodes):
                try:
                    # COSTRUZIONE DEL TESTO SEMANTICO (Contextual Prompting)
                    # Adattiamo il testo in base al tipo di nodo per migliorare il retrieval
                    if label == "Exploit":
                        # Per gli exploit di Kali, includiamo piattaforma e tipo di attacco
                        safe_text = f"Exploit: {node['desc']}. Platform: {node.get('platform', 'N/A')}. Type: {node.get('type', 'N/A')}"
                    elif label == "Vulnerability":
                        # Per le CVE usiamo la descrizione ufficiale NIST arricchita
                        safe_text = f"Vulnerability {node['id']}: {node['desc'][:1200]}"
                    else:
                        # Default per Technique e Weakness
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
        """Crea o ricrea gli indici vettoriali su Neo4j per tutte le etichette."""
        print("🏗️ Configurazione indici vettoriali (1024 dimensioni)...")
        with self.driver.session() as session:
            # Lista degli indici da gestire
            indices = [
                ("technique_vector_index", "Technique"),
                ("weakness_vector_index", "Weakness"),
                ("vulnerability_vector_index", "Vulnerability"),
                ("exploit_vector_index", "Exploit")
            ]
            
            for index_name, label in indices:
                # Eliminiamo eventuali vecchi indici se necessario (opzionale)
                # session.run(f"DROP INDEX `{index_name}` IF EXISTS")
                
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
    # Configurazione connessioni (Kali VM -> Host)
    URI, OLLAMA_URL = "bolt://10.0.2.2:7687", "http://10.0.2.2:11434"
    
    agent = VectorialistAgent(URI, "neo4j", "ciaociao", OLLAMA_URL)
    try:
        # 1. Generiamo i vettori per i nuovi nodi caricati (Exploit e CVE)
        # force_update=False permette di non rifare quelli già esistenti
        agent.generate_embeddings("Vulnerability", force_update=False)
        agent.generate_embeddings("Exploit", force_update=False)
        
        # 2. Se hai modificato o vuoi rinfrescare Technique e Weakness, usa True
        agent.generate_embeddings("Technique", force_update=False)
        agent.generate_embeddings("Weakness", force_update=False)
        
        # 3. Creazione finale degli indici per rendere il database interrogabile
        agent.create_indices()
        
        print("\n✨ Operazione di embedding completata con successo!")
        print("🚀 Il grafo è ora pronto per essere interrogato dall'HybridRAGAgent.")
    finally:
        agent.close()