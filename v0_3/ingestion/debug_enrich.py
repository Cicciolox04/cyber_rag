import json, os, glob
from neo4j import GraphDatabase

class CVEInspector:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def debug_compare(self, file_path):
        print(f"🔍 Ispezione file: {file_path}")
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Estrarre primi 5 ID dal JSON
        json_ids = []
        items = data.get('cve_items', [])
        for item in items[:5]:
            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            if cve_id: json_ids.append(f"'{cve_id}'")
        
        print(f"📄 Esempi ID nel JSON: {', '.join(json_ids)}")

        # Estrarre primi 5 ID dal DB
        db_ids = []
        with self.driver.session() as session:
            res = session.run("MATCH (v:Vulnerability) RETURN v.id LIMIT 5")
            db_ids = [f"'{r['v.id']}'" for r in res]
        
        print(f"🗄️ Esempi ID nel Database: {', '.join(db_ids)}")

if __name__ == "__main__":
    inspector = CVEInspector("bolt://10.0.2.2:7687", "neo4j", "ciaociao")
    inspector.debug_compare("../data/cve_data/CVE-2022.json")