from neo4j import GraphDatabase
import sys

# --- CONFIGURAZIONE ---
URI = "bolt://10.0.2.2:7687"
USER = "neo4j"
PASSWORD = "ciaociao"

class GraphFinalizer:
    def __init__(self, uri, user, password):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            print("✅ Connessione a Neo4j riuscita.")
        except Exception as e:
            print(f"❌ Errore di connessione: {e}")
            sys.exit(1)

    def close(self):
        self.driver.close()

    def run_inference(self):
        with self.driver.session() as session:
            print("\n🧠 [Fase 1] Creazione legami HAS_WEAKNESS (Inference A)...")
            # Collega Tecniche a CWE passando per i Pattern
            query_a = """
            MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p:Pattern)-[:EXPLOITS]->(w:Weakness)
            MERGE (t)-[r:HAS_WEAKNESS]->(w)
            ON CREATE SET r.origin = "Inferred via " + p.id
            RETURN count(r) as count
            """
            res_a = session.run(query_a).single()
            print(f"   -> Create {res_a['count']} relazioni HAS_WEAKNESS.")

            print("\n🏛️ [Fase 2] Creazione legami INFERRED_COMPLIANCE (Inference B)...")
            # Collega Tecniche a Requisiti (ISO/NIST) passando per le CWE
            query_b = """
            MATCH (t:Technique)-[:HAS_WEAKNESS]->(w:Weakness)-[:VIOLATES]->(r:Requirement)
            MERGE (t)-[v:INFERRED_COMPLIANCE]->(r)
            ON CREATE SET v.method = "Graph Traversal (T-W-R)"
            RETURN count(v) as count
            """
            res_b = session.run(query_b).single()
            print(f"   -> Creati {res_b['count']} ponti di compliance.")

    def run_checkpoint(self):
        print("\n📊 [Fase 3] Verifica finale del Database (Checkpoint)...")
        check_query = """
        MATCH (n)
        RETURN labels(n)[0] as Etichetta, count(n) as Totale
        UNION
        MATCH ()-[r]->()
        RETURN type(r) as Etichetta, count(r) as Totale
        """
        with self.driver.session() as session:
            results = session.run(check_query)
            print(f"{'Etichetta':<25} | {'Totale':<10}")
            print("-" * 40)
            for record in results:
                print(f"{record['Etichetta']:<25} | {record['Totale']:<10}")

if __name__ == "__main__":
    finalizer = GraphFinalizer(URI, USER, PASSWORD)
    try:
        finalizer.run_inference()
        finalizer.run_checkpoint()
        print("\n✨ Configurazione del grafo completata con successo!")
    finally:
        finalizer.close()