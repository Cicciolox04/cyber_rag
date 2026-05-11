import os, json, glob
from neo4j import GraphDatabase

class KnowledgeBaseEnricher:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def build_knowledge_base(self, folder_path):
        abs_path = os.path.abspath(folder_path)
        files = glob.glob(os.path.join(abs_path, "CVE-*.json"))
        print(f"🚀 Avvio Espansione Knowledge Base: {abs_path}")

        with self.driver.session() as session:
            for file_path in files:
                print(f"📖 Integrazione Intelligence: {os.path.basename(file_path)}...")
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                records = data.get('cve_items', [])
                batch = []

                for rec in records:
                    cve_id = rec.get('id')
                    
                    # Estrazione CWE
                    cwe_id = None
                    for w in rec.get('weaknesses', []):
                        for desc_wrapper in w.get('description', []):
                            val = desc_wrapper.get('value')
                            if val and val.startswith('CWE-'):
                                cwe_id = val.replace('CWE-', '').strip()
                                break
                        if cwe_id: break
                    
                    # Estrazione Descrizione NIST
                    description = ""
                    for d in rec.get('descriptions', []):
                        if d.get('lang') == 'en':
                            description = d.get('value')
                            break

                    if cve_id:
                        batch.append({
                            'id': cve_id.strip(),
                            'cwe': cwe_id if cwe_id else None,
                            'desc': description.strip() if description else "Descrizione non disponibile"
                        })

                if batch:
                    # LOGICA MERGE: Crea se manca, aggiorna se esiste
                    session.run("""
                        UNWIND $data as item
                        MERGE (v:Vulnerability {id: item.id})
                        ON CREATE SET v.cwe_id = item.cwe,
                                      v.description = item.desc,
                                      v.source = 'NIST NVD',
                                      v.status = 'KB_ONLY'
                        ON MATCH SET v.cwe_id = item.cwe,
                                     v.description = item.desc,
                                     v.status = 'ENRICHED'
                    """, data=batch)
                    print(f"   ✅ {len(batch)} nodi integrati nel Grafo.")

if __name__ == "__main__":
    URI, USER, PW = "bolt://10.0.2.2:7687", "neo4j", "ciaociao"
    enricher = KnowledgeBaseEnricher(URI, USER, PW)
    enricher.build_knowledge_base("../data/cve_data")