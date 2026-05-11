from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings

class RAGTester:
    def __init__(self, uri, user, password, ollama_url):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)

    def close(self):
        self.driver.close()

    def test_semantic_to_compliance(self, user_query):
        """
        Test ibrido: Cerca semanticamente un exploit e trova quali requisiti viola.
        """
        print(f"\n🔍 Query Utente: '{user_query}'")
        
        # 1. Generiamo il vettore per la query
        query_vector = self.embeddings.embed_query(user_query)
        
        with self.driver.session() as session:
            # 2. Query Cypher Ibrida: Ricerca Vettoriale + Traversing del Grafo
            query = """
            CALL db.index.vector.queryNodes('exploit_vector_index', 3, $vector)
            YIELD node AS exploit, score
            
            OPTIONAL MATCH (exploit)-[:EXPLOITS_VULNERABILITY]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:INSTANCE_OF]->(w:Weakness)
            OPTIONAL MATCH (w)-[:VIOLATES]->(r:Requirement)
            
            RETURN exploit.id AS id, 
                   exploit.description AS desc, 
                   score, 
                   collect(DISTINCT r.id) AS violated_requirements,
                   v.id AS cve
            """
            
            results = session.run(query, vector=query_vector)
            
            print(f"{'SCORE':<8} | {'ID EXPLOIT':<12} | {'CVE':<15} | {'COMPLIANCE VIOLATED'}")
            print("-" * 80)
            for res in results:
                reqs = ", ".join(res['violated_requirements']) if res['violated_requirements'] else "Nessuna relazione trovata"
                print(f"{res['score']:.4f} | {res['id']:<12} | {str(res['cve']):<15} | {reqs}")
                print(f"   ↳ Desc: {res['desc'][:100]}...")

if __name__ == "__main__":
    URI, OLLAMA_URL = "bolt://10.0.2.2:7687", "http://10.0.2.2:11434"
    tester = RAGTester(URI, "neo4j", "ciaociao", OLLAMA_URL)
    
    try:
        # Test 1: Ricerca tecnica specifica
        tester.test_semantic_to_compliance("buffer overflow in windows kernel")
        
        # Test 2: Ricerca per concetto di vulnerabilità web
        tester.test_semantic_to_compliance("remote code execution via sql injection")
        
    finally:
        tester.close()