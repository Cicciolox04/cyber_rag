import os, json, glob
from neo4j import GraphDatabase

class NVD2ItemsEnricher:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def enrich_from_json_folder(self, folder_path):
        abs_path = os.path.abspath(folder_path)
        files = glob.glob(os.path.join(abs_path, "CVE-*.json"))
        print(f"📂 Elaborazione cartella: {abs_path}")

        with self.driver.session() as session:
            for file_path in files:
                print(f"📖 Analisi chirurgica: {os.path.basename(file_path)}...")
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # La tua chiave radice è 'cve_items'
                records = data.get('cve_items', [])
                batch = []

                for rec in records:
                    # L'ID è una chiave diretta del record
                    cve_id = rec.get('id')
                    
                    # 1. Estrazione CWE dal percorso scoperto
                    cwe_id = None
                    for w in rec.get('weaknesses', []):
                        for desc_wrapper in w.get('description', []):
                            val = desc_wrapper.get('value')
                            if val and val.startswith('CWE-'):
                                cwe_id = val
                                break
                        if cwe_id: break
                    
                    # 2. Estrazione Descrizione (filtro per lingua inglese)
                    description = ""
                    for d in rec.get('descriptions', []):
                        if d.get('lang') == 'en':
                            description = d.get('value')
                            break

                    if cve_id:
                        batch.append({
                            'id': cve_id.strip(),
                            'cwe': cwe_id.strip() if cwe_id else None,
                            'desc': description.strip() if description else ""
                        })

                if batch:
                    # Aggiornamento massivo delle proprietà
                    session.run("""
                        UNWIND $data as item
                        MATCH (v:Vulnerability {id: item.id})
                        SET v.cwe_id = item.cwe,
                            v.description = item.desc
                    """, data=batch)
                    print(f"   ✅ {len(batch)} record processati e aggiornati su Neo4j.")
                else:
                    print(f"   ⚠️ Nessun dato utile trovato in {os.path.basename(file_path)}.")

if __name__ == "__main__":
    enricher = NVD2ItemsEnricher("bolt://10.0.2.2:7687", "neo4j", "ciaociao")
    enricher.enrich_from_json_folder("../data/cve_data")