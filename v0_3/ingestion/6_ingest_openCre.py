import json
from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
JSON_FILE = '../data/opencre_map.json'
URI = "bolt://10.0.2.2:7687"
USER = "neo4j"
PASSWORD = "ciaociao"

def ingest_opencre_graph():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    print("📜 Ingestione OpenCRE: Collegamento vulnerabilità agli Standard...")
    
    with open(JSON_FILE, "r", encoding="utf-8") as f:
        opencre_data = json.load(f)

    with driver.session() as session:
        count_reqs = 0
        count_links = 0
        
        for cwe_id, mappings in opencre_data.items():
            # Pulizia e normalizzazione ID CWE
            clean_cwe = f"CWE-{cwe_id}" if not str(cwe_id).startswith("CWE-") else cwe_id
            
            for m in mappings:
                # Creiamo un ID unico per il requisito (es. ISO27001-A.12.6.1)
                req_id = f"{m['standard']}-{m['section']}"
                
                # 1. Crea il nodo del Requisito
                session.run("""
                    MERGE (r:Requirement {id: $req_id})
                    SET r.standard = $standard,
                        r.section = $section,
                        r.name = $cre_name
                """, req_id=req_id, standard=m['standard'], 
                     section=m['section'], cre_name=m['cre_name'])
                count_reqs += 1

                # 2. Crea la relazione VIOLATES
                # Il match avviene sulla CWE che hai già caricato
                res = session.run("""
                    MATCH (w:Weakness {id: $cwe_id})
                    MATCH (r:Requirement {id: $req_id})
                    MERGE (w)-[:VIOLATES]->(r)
                    RETURN count(r) as linked
                """, cwe_id=clean_cwe, req_id=req_id).single()
                
                if res['linked'] > 0:
                    count_links += 1
                    
    driver.close()
    print(f"✨ MISSIONE COMPIUTA!")
    print(f"   - Requisiti caricati: {count_reqs}")
    print(f"   - Collegamenti 'VIOLATES' creati: {count_links}")

if __name__ == "__main__":
    ingest_opencre_graph()