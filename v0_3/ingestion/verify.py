import json
from neo4j import GraphDatabase

class GraphDiagnosticAgent:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def run_diagnostics(self):
        queries = {
            "1_VULNERABILITY_EXPLOIT_BRIDGE": """
                MATCH (v:Vulnerability)
                OPTIONAL MATCH (v)-[r:INSTANCE_OF]->(w:Weakness)
                OPTIONAL MATCH (v)<-[:EXPLOITS_VULNERABILITY]-(e:Exploit)
                RETURN v.id AS CVE, 
                       w.id AS Linked_CWE, 
                       count(e) AS Exploit_Count,
                       v.embedding IS NOT NULL AS Is_Vectorized
                LIMIT 20
            """,
            "2_TECHNIQUE_PATTERN_DENSITY": """
                MATCH (t:Technique)
                OPTIONAL MATCH (t)-[:MAPS_TO_PATTERN]->(p:Pattern)
                RETURN t.id AS Technique, 
                       count(p) AS Patterns_Mapped
                ORDER BY Patterns_Mapped DESC
                LIMIT 15
            """,
            "3_COMPLIANCE_THREAT_MAP": """
                MATCH (e:Exploit)-[:DIRECTLY_THREATENS]->(r:Requirement)
                RETURN r.standard AS Standard, 
                       r.section AS Section, 
                       count(e) AS Active_Exploits
                ORDER BY Active_Exploits DESC
            """,
            "4_CWE_REQUIREMENT_IMPACT": """
                MATCH (w:Weakness)-[:VIOLATES]->(r:Requirement)
                RETURN w.id AS CWE, 
                       count(r) AS Standards_Violated
                ORDER BY Standards_Violated DESC
                LIMIT 10
            """,
            "5_VECTOR_INDEX_STATUS": """
                MATCH (n)
                WHERE n:Technique OR n:Weakness OR n:Vulnerability OR n:Exploit
                WITH labels(n)[0] AS Category, n
                RETURN Category,
                       count(n) AS Total_Nodes,
                       count(n.embedding) AS Vectorized_Nodes
            """,
            "6_ORPHAN_CVE_CHECK": """
                MATCH (v:Vulnerability)
                WHERE NOT (v)-[:INSTANCE_OF]->(:Weakness)
                RETURN count(v) AS Orphan_CVE_Count
            """
        }

        results = {}
        
        with self.driver.session() as session:
            print("🚀 Avvio diagnostica sequenziale del Grafo Cyber...")
            for name, query in queries.items():
                print(f"--- Esecuzione {name} ---")
                res = session.run(query)
                results[name] = [dict(record) for record in res]
        
        return results

if __name__ == "__main__":
    # Parametri derivati dai tuoi file di ingestion
    URI = "bolt://10.0.2.2:7687" 
    USER = "neo4j"
    PASS = "ciaociao"

    diag = GraphDiagnosticAgent(URI, USER, PASS)
    try:
        output = diag.run_diagnostics()
        # Stampiamo in JSON per facilitare l'analisi successiva
        print("\n--- OUTPUT FINALE (COPIA DA QUI) ---")
        print(json.dumps(output, indent=2))
        print("--- FINE OUTPUT ---")
    finally:
        diag.close()