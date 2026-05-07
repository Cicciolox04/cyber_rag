import json
from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
JSON_FILE = '../data/capec.json'
URI = "bolt://10.0.2.2:7687"
USER = "neo4j"
PASSWORD = "ciaociao"

def ingest_capec_graph():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    
    print("🔍 Analisi file CAPEC e creazione relazioni...")
    with open(JSON_FILE, 'r') as f:
        capec_data = json.load(f)

    with driver.session() as session:
        count_patterns = 0
        count_rels = 0
        
        for obj in capec_data['objects']:
            if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                name = obj.get('name')
                desc = obj.get('description', 'N/A')
                
                capec_id = "N/A"
                related_cwes = []
                
                # Estrazione ID e riferimenti CWE [cite: 89]
                if obj.get('external_references'):
                    for ref in obj['external_references']:
                        source = ref.get('source_name', '').lower()
                        ext_id = ref.get('external_id')
                        if source == 'capec': 
                            capec_id = ext_id
                        elif source == 'cwe': 
                            related_cwes.append(ext_id)
                
                if capec_id == "N/A": continue

                # 1. Creazione del nodo Pattern
                query_node = """
                MERGE (p:Pattern {id: $id})
                SET p.name = $name, p.description = $desc
                """
                session.run(query_node, id=capec_id, name=name, desc=desc)
                count_patterns += 1

                # 2. Creazione della relazione verso la Weakness (CWE)
                for cwe_id in related_cwes:
                    query_rel = """
                    MATCH (p:Pattern {id: $p_id})
                    MATCH (w:Weakness {id: $w_id})
                    MERGE (p)-[:EXPLOITS]->(w)
                    """
                    session.run(query_rel, p_id=capec_id, w_id=cwe_id)
                    count_rels += 1
                    
    driver.close()
    print(f"✨ Caricati {count_patterns} Pattern e create {count_rels} relazioni 'EXPLOITS'!")

if __name__ == "__main__":
    ingest_capec_graph()