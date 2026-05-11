from neo4j import GraphDatabase

class SuperLinker:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def clean_and_link(self):
        with self.driver.session() as session:
            print("🧹 Fase 1: Pulizia e Normalizzazione proprietà...")
            # Rimuoviamo spazi e normalizziamo il prefisso 'CWE-' su tutte le Vulnerability
            session.run("""
                MATCH (v:Vulnerability) 
                WHERE v.cwe_id IS NOT NULL
                SET v.cwe_id = trim(replace(v.cwe_id, 'CWE-', ''))
            """)
            
            # Facciamo lo stesso sui nodi Weakness per essere sicuri
            session.run("""
                MATCH (w:Weakness)
                SET w.id = trim(replace(w.id, 'CWE-', ''))
            """)
            print("   ✅ Proprietà normalizzate (formato numerico puro).")

            print("🔗 Fase 2: Creazione massiva relazioni INSTANCE_OF...")
            # Ora che entrambi sono numeri puri, il match è garantito
            result = session.run("""
                MATCH (v:Vulnerability), (w:Weakness)
                WHERE v.cwe_id = w.id
                MERGE (v)-[r:INSTANCE_OF]->(w)
                RETURN count(r) as count
            """)
            print(f"   ✨ Creati {result.single()['count']} collegamenti INSTANCE_OF!")

            print("🧠 Fase 3: Ricalcolo inferenze Compliance...")
            # Una volta collegati CVE e CWE, i Requisiti NIST/ISO si attivano
            inf = session.run("""
                MATCH (e:Exploit)-[:EXPLOITS_VULNERABILITY]->(v:Vulnerability)-[:INSTANCE_OF]->(w:Weakness)-[:VIOLATES]->(r:Requirement)
                MERGE (e)-[rel:DIRECTLY_THREATENS]->(r)
                RETURN count(rel) as count
            """)
            print(f"   🚀 Ponti DIRECTLY_THREATENS attivati: {inf.single()['count']}")

if __name__ == "__main__":
    linker = SuperLinker("bolt://10.0.2.2:7687", "neo4j", "ciaociao")
    linker.clean_and_link()