import re
import pandas as pd
import json
import os
import glob
from neo4j import GraphDatabase

class KnowledgeIngestorAgent:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.setup_constraints()

    def setup_constraints(self):
        """Crea vincoli di unicità per garantire l'integrità e velocizzare l'ingestione."""
        print("⚙️ Configurazione vincoli di unicità (Constraints)...")
        # Elenco dei vincoli per ogni etichetta del grafo
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (w:Weakness) REQUIRE w.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Pattern) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Requirement) REQUIRE r.id IS UNIQUE"
        ]
        with self.driver.session() as session:
            for query in constraints:
                try:
                    session.run(query)
                except Exception as e:
                    print(f"   ⚠️ Nota sul vincolo: {e}")
        print("✅ Vincoli pronti.")
    
    def close(self):
        self.driver.close()

    def _find_header_row(self, file_path):
        """Logica interna per individuare l'inizio dei dati CWE."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if 'CWE-ID' in line and 'Name' in line:
                    return i
        return 0

    def build_knowledge_base(self, folder_path):
        """
        Carica esclusivamente le CVE comprese tra il 2023 e il 2026.
        """
        abs_path = os.path.abspath(folder_path)
        all_files = glob.glob(os.path.join(abs_path, "CVE-*.json"))
        
        # Filtro: teniamo solo i file che contengono gli anni 2023, 2024, 2025 o 2026 nel nome
        target_years = ["2017", "2019", "2024", "2025", "2021"]
        files = [f for f in all_files if any(year in os.path.basename(f) for year in target_years)]
        
        print(f"🚀 Espansione Knowledge Base (Target: 2017, 2019, 2021, 2024, 2025) da: {abs_path}")
        print(f"📂 File pronti per l'ingestione: {[os.path.basename(f) for f in files]}")

        with self.driver.session() as session:
            for file_path in files:
                print(f"📖 Analisi file NIST: {os.path.basename(file_path)}...")
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                records = data.get('cve_items', [])
                batch = []

                for rec in records:
                    cve_id = rec.get('id')
                    cwe_id = None
                    for w in rec.get('weaknesses', []):
                        for desc_wrapper in w.get('description', []):
                            val = desc_wrapper.get('value')
                            if val and val.startswith('CWE-'):
                                cwe_id = val.replace('CWE-', '').strip()
                                break
                        if cwe_id: break
                    
                    description = ""
                    for d in rec.get('descriptions', []):
                        if d.get('lang') == 'en':
                            description = d.get('value')
                            break

                    if cve_id:
                        batch.append({
                            'id': cve_id.strip(),
                            'cwe': cwe_id, 
                            'desc': description.strip() if description else "N/A"
                        })

                if batch:
                    # Grazie ai vincoli, il MERGE non esegue più scansioni totali della tabella
                    session.run("""
                        UNWIND $data as item
                        MERGE (v:Vulnerability {id: item.id})
                        ON CREATE SET v.cwe_id = item.cwe, 
                                      v.description = item.desc,
                                      v.status = 'KB_ONLY'
                        ON MATCH SET v.cwe_id = item.cwe, 
                                     v.description = item.desc
                    """, data=batch)
                    print(f"   ✅ {len(batch)} record integrati.")

    def ingest_exploitdb(self, csv_path):
        """Carica exploit da Exploit-DB e collega a CVE esistenti o nuove."""
        print(f"💣 Ingestione Exploit-DB da {csv_path}...")
        df = pd.read_csv(csv_path, low_memory=False)
        base_path = "/usr/share/exploitdb/"

        with self.driver.session() as session:
            count_exploit = 0
            for _, row in df.iterrows():
                edb_id = str(row['id'])
                full_file_path = base_path + str(row['file'])
                
                session.run("""
                    MERGE (e:Exploit {id: $id})
                    SET e.description = $desc, 
                        e.file_path = $path, 
                        e.type = $type, 
                        e.platform = $platform,
                        e.verified = $verified
                """, id=edb_id, desc=str(row['description']), path=full_file_path, 
                     type=row['type'], platform=row['platform'], verified=bool(row['verified']))
                count_exploit += 1

                codes = str(row.get('codes', ''))
                if codes and codes != 'nan':
                    cve_list = re.findall(r'CVE-\d{4}-\d+', codes)
                    for cve_id in cve_list:
                        # Colleghiamo l'exploit alla vulnerabilità, aggiornandone lo status
                        session.run("""
                            MERGE (v:Vulnerability {id: $cve_id})
                            WITH v
                            MATCH (e:Exploit {id: $edb_id})
                            MERGE (e)-[:EXPLOITS_VULNERABILITY]->(v)
                            SET v.status = 'HAS_EXPLOIT'
                        """, cve_id=cve_id, edb_id=edb_id)
                        
        print(f"✨ Caricati {count_exploit} Exploit e mappati su CVE!")

    def ingest_cwe(self, csv_path):
        """Carica nodi Weakness normalizzati a formato numerico puro."""
        print(f"📊 Popolamento grafo con debolezze CWE...")
        header_idx = self._find_header_row(csv_path)
        df = pd.read_csv(csv_path, low_memory=False, skiprows=header_idx, index_col=False)
        df.columns = [c.strip() for c in df.columns]

        with self.driver.session() as session:
            count = 0
            for _, row in df.iterrows():
                raw_id = str(row.get('CWE-ID', '')).strip()
                name = str(row.get('Name', 'Unknown Weakness')).strip()
                description = str(row.get('Description', '')).strip()

                if not raw_id or raw_id.lower() in ['nan', ''] or not description:
                    continue

                # Normalizzazione: usiamo solo il numero per facilitare il match
                clean_id = raw_id.replace('CWE-', '').strip()
                
                session.run("""
                    MERGE (w:Weakness {id: $id})
                    SET w.name = $name, w.description = $description, w.source = 'MITRE CWE'
                """, id=clean_id, name=name, description=description)
                count += 1
        print(f"✨ {count} nodi Weakness pronti.")

    def ingest_capec(self, json_path):
        """Carica nodi Pattern e crea relazioni EXPLOITS verso Weakness."""
        print(f"🔍 Analisi file CAPEC e creazione relazioni...")
        with open(json_path, 'r') as f:
            capec_data = json.load(f)

        with self.driver.session() as session:
            count_patterns = 0
            for obj in capec_data['objects']:
                if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                    name = obj.get('name')
                    desc = obj.get('description', 'N/A')
                    capec_id = "N/A"
                    related_cwes = []
                    
                    if obj.get('external_references'):
                        for ref in obj['external_references']:
                            source = ref.get('source_name', '').lower()
                            ext_id = ref.get('external_id')
                            if source == 'capec': capec_id = ext_id
                            elif source == 'cwe': 
                                # Puliamo anche qui per coerenza
                                related_cwes.append(str(ext_id).replace('CWE-', ''))
                    
                    if capec_id == "N/A": continue

                    session.run("""
                        MERGE (p:Pattern {id: $id})
                        SET p.name = $name, p.description = $desc
                    """, id=capec_id, name=name, desc=desc)
                    count_patterns += 1

                    for cwe_id in related_cwes:
                        session.run("""
                            MATCH (p:Pattern {id: $p_id})
                            MATCH (w:Weakness {id: $w_id})
                            MERGE (p)-[:EXPLOITS]->(w)
                        """, p_id=capec_id, w_id=cwe_id)
        print(f"✨ Pattern caricati: {count_patterns}")

    def ingest_mitre(self, json_path):
        """Carica esclusivamente nodi Technique."""
        print(f"📖 Caricamento tecniche MITRE ATT&CK...")
        with open(json_path, 'r') as f:
            mitre_data = json.load(f)

        with self.driver.session() as session:
            count_tech = 0
            for obj in mitre_data['objects']:
                if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                    name = obj.get('name')
                    desc = obj.get('description', 'N/A')
                    tech_id = "N/A"
                    if obj.get('external_references'):
                        for ref in obj['external_references']:
                            if ref.get('source_name') == 'mitre-attack':
                                tech_id = ref.get('external_id')
                                break
                    
                    if tech_id == "N/A": continue

                    session.run("""
                        MERGE (t:Technique {id: $id})
                        SET t.name = $name, t.description = $desc
                    """, id=tech_id, name=name, desc=desc)
                    count_tech += 1
        print(f"✨ Tecniche caricate: {count_tech}")

    def ingest_opencre(self, json_path):
        """Carica i Requisiti e i legami VIOLATES dalle CWE."""
        print(f"📜 Ingestione OpenCRE: Mapping verso Standard di Compliance...")
        with open(json_path, "r", encoding="utf-8") as f:
            opencre_data = json.load(f)

        with self.driver.session() as session:
            count_reqs = 0
            for cwe_id, mappings in opencre_data.items():
                # Pulizia ID CWE per match numerico
                clean_cwe = str(cwe_id).replace('CWE-', '').strip()
                for m in mappings:
                    req_id = f"{m['standard']}-{m['section']}"
                    session.run("""
                        MERGE (r:Requirement {id: $req_id})
                        SET r.standard = $standard, r.section = $section, r.name = $cre_name
                    """, req_id=req_id, standard=m['standard'], section=m['section'], cre_name=m['cre_name'])
                    count_reqs += 1

                    session.run("""
                        MATCH (w:Weakness {id: $cwe_id})
                        MATCH (r:Requirement {id: $req_id})
                        MERGE (w)-[:VIOLATES]->(r)
                    """, cwe_id=clean_cwe, req_id=req_id)
        print(f"✨ Requisiti e mapping di Compliance completati.")

    def verify(self):
        """Verifica lo stato attuale del database."""
        print("\n📊 --- STATISTICHE GRAFO ---")
        query = """
        MATCH (n) RETURN labels(n)[0] as Etichetta, count(n) as Totale
        UNION ALL
        MATCH ()-[r]->() RETURN type(r) as Etichetta, count(r) as Totale
        """
        with self.driver.session() as session:
            res = session.run(query)
            for record in res:
                print(f"{record['Etichetta']:<25} | {record['Totale']}")

if __name__ == "__main__":
    URI = "bolt://10.0.2.2:7687"
    agent = KnowledgeIngestorAgent(URI, "neo4j", "ciaociao")
    try:
        # Step 1: Caricamento Strutture di Base
        agent.ingest_cwe('../data/cwe_list.csv')
        agent.ingest_capec('../data/capec.json')
        agent.ingest_mitre('../data/mitre.json')
        agent.ingest_opencre('../data/opencre_map.json')

        # Step 2: Espansione Intelligence e Exploit Reali
        agent.build_knowledge_base('../data/cve_data')
        agent.ingest_exploitdb('/usr/share/exploitdb/files_exploits.csv')
        
        agent.verify()
    finally:
        agent.close()