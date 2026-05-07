import re
from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
URI = "bolt://10.0.2.2:7687"
AUTH = ("neo4j", "ciaociao")

def ingest_mitre_cwe_links():
    driver = GraphDatabase.driver(URI, auth=AUTH)
    # Regex per trovare CWE- seguito da numeri
    re_cwe = re.compile(r"CWE-(\d+)", re.IGNORECASE)

    print("🔎 Scansione descrizioni MITRE per estrazione CWE...")
    
    with driver.session() as session:
        # 1. Recuperiamo tutte le tecniche che hanno una descrizione
        techniques = session.run("MATCH (t:Technique) WHERE t.description IS NOT NULL RETURN t.id as id, t.description as desc").data()
        
        count_links = 0
        for tech in techniques:
            # Trova tutti i codici CWE nella descrizione
            found_cwes = re_cwe.findall(tech['desc'])
            
            for cwe_num in set(found_cwes):
                cwe_id = f"CWE-{cwe_num}"
                
                # Crea la relazione HAS_WEAKNESS se la CWE esiste nel grafo
                res = session.run("""
                    MATCH (t:Technique {id: $tid})
                    MATCH (w:Weakness {id: $wid})
                    MERGE (t)-[:HAS_WEAKNESS]->(w)
                    RETURN count(w) as f
                """, tid=tech['id'], wid=cwe_id).single()
                
                if res['f'] > 0:
                    count_links += 1

    driver.close()
    print(f"✨ FINE: Creati {count_links} nuovi archi HAS_WEAKNESS!")

if __name__ == "__main__":
    ingest_mitre_cwe_links()