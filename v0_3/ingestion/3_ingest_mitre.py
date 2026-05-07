import json
from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
JSON_FILE = '../data/enterprise-attack.json'
URI = "bolt://10.0.2.2:7687"
USER = "neo4j"
PASSWORD = "ciaociao"

def ingest_mitre_nodes():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    print(f"📖 Caricamento tecniche da {JSON_FILE}...")
    
    with open(JSON_FILE, 'r') as f:
        mitre_data = json.load(f)

    with driver.session() as session:
        count_tech = 0
        for obj in mitre_data['objects']:
            # Filtriamo solo le tecniche (attack-pattern) attive
            if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                name = obj.get('name')
                desc = obj.get('description', 'N/A')
                
                # Estrazione ID MITRE (es. T1059)
                tech_id = "N/A"
                if obj.get('external_references'):
                    for ref in obj['external_references']:
                        if ref.get('source_name') == 'mitre-attack':
                            tech_id = ref.get('external_id')
                            break
                
                if tech_id == "N/A": continue

                # Creazione del nodo Technique
                session.run("""
                    MERGE (t:Technique {id: $id})
                    SET t.name = $name, t.description = $desc
                """, id=tech_id, name=name, desc=desc)
                count_tech += 1

    driver.close()
    print(f"✨ Creati {count_tech} nodi Technique!")

if __name__ == "__main__":
    ingest_mitre_nodes()