from neo4j import GraphDatabase
import json

# Credenziali Neo4j
URI = "bolt://10.0.2.2:7687"
AUTH = ("neo4j", "ciaociao")

def ingest_mitre_to_neo4j(json_file):
    driver = GraphDatabase.driver(URI, auth=AUTH)
    
    # Inizializzazione contatori
    count_tech = 0
    count_links = 0
    
    print(f"📖 Lettura del file: {json_file}...")
    with open(json_file, 'r') as f:
        mitre_data = json.load(f)

    with driver.session() as session:
        for obj in mitre_data['objects']:
            if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                tech_id = "N/A"
                related_capecs = []
                
                if obj.get('external_references'):
                    for ref in obj['external_references']:
                        source = ref.get('source_name', '').lower()
                        ext_id = ref.get('external_id')
                        if source == 'mitre-attack':
                            tech_id = ext_id
                        elif source == 'capec':
                            # Pulizia ID: assicuriamoci che sia 'CAPEC-XXXX'
                            clean_capec = str(ext_id).strip().upper()
                            if not clean_capec.startswith("CAPEC-"):
                                clean_capec = f"CAPEC-{clean_capec}"
                            related_capecs.append(clean_capec)

                if tech_id == "N/A": continue

                # Crea/Aggiorna la Tecnica
                session.run("MERGE (t:Technique {id: $id}) SET t.name = $name", 
                            id=tech_id, name=obj.get('name'))
                count_tech += 1
                
                # Prova a collegare i CAPEC
                for c_id in related_capecs:
                    # Usiamo una query che non fallisce se il CAPEC non esiste ancora
                    # ma incrementa il contatore solo se la relazione viene creata
                    res = session.run("""
                        MATCH (p:Pattern {id: $p_id})
                        MATCH (t:Technique {id: $t_id})
                        MERGE (t)-[:MAPS_TO_PATTERN]->(p)
                        RETURN count(p) as found
                    """, p_id=c_id, t_id=tech_id).single()
                    
                    if res and res['found'] > 0:
                        count_links += 1

    driver.close()
    print(f"✅ Ingestion completata!")
    print(f"   - Tecniche caricate: {count_tech}")
    print(f"   - Relazioni MAPS_TO_PATTERN create: {count_links}")

# Esegui l'ingestion
if __name__ == "__main__":
    ingest_mitre_to_neo4j('../data/enterprise-attack.json')