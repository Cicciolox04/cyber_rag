from neo4j import GraphDatabase
import json

# Credenziali Neo4j
URI = "bolt://localhost:7687"
AUTH = ("neo4j", "tua_password")

def ingest_mitre_to_neo4j(json_file):
    driver = GraphDatabase.driver(URI, auth=AUTH)
    with open(json_file, 'r') as f:
        mitre_data = json.load(f)

    with driver.session() as session:
        for obj in mitre_data['objects']:
            if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                # Estrazione dati migliorata rispetto alla versione precedente 
                ext_id = "N/A"
                if obj.get('external_references'):
                    for ref in obj['external_references']:
                        if ref.get('source_name') == 'mitre-attack':
                            ext_id = ref.get('external_id')
                
                # Query Cypher per creare il nodo (evita duplicati con MERGE)
                query = """
                MERGE (t:Technique {id: $id})
                SET t.name = $name,
                    t.description = $desc,
                    t.platforms = $platforms,
                    t.phases = $phases
                """
                session.run(query, 
                    id=ext_id, 
                    name=obj.get('name'), 
                    desc=obj.get('description', ''),
                    platforms=obj.get('x_mitre_platforms', []),
                    phases=[p['phase_name'] for p in obj.get('kill_chain_phases', [])]
                )
    driver.close()
    print("✅ MITRE Techniques caricate nel Grafo!")

# Esegui l'ingestion usando il file che già possiedi 
ingest_mitre_to_neo4j('../data/enterprise-attack.json')