import pandas as pd
import json
from neo4j import GraphDatabase

class KnowledgeIngestorAgent:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def _find_header_row(self, file_path):
        """Logica interna per individuare l'inizio dei dati CWE."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if 'CWE-ID' in line and 'Name' in line:
                    return i
        return 0

    def ingest_cwe(self, csv_path):
        """Carica esclusivamente nodi Weakness."""
        print(f"📊 Analisi file CWE e popolamento grafo...")
        header_idx = self._find_header_row(csv_path)
        df = pd.read_csv(csv_path, low_memory=False, skiprows=header_idx)
        df.columns = [c.strip() for c in df.columns]

        with self.driver.session() as session:
            count = 0
            for index, row in df.iterrows():
                # Usa l'indice come ID grezzo come da script originale
                cwe_raw_id = str(index).strip() 
                name = str(row.get('CWE-ID', '')).strip()
                
                if name.lower() in ['base', 'variant', 'class', 'nan']:
                    name = str(row.get('Name', 'Unknown Weakness')).strip()

                description = str(row.get('Description', '')).strip()
                if not cwe_raw_id or cwe_raw_id.lower() in ['nan', 'cwe-id'] or not description or description.lower() == 'nan':
                    continue

                cwe_id = f"CWE-{cwe_raw_id}" if "CWE" not in cwe_raw_id.upper() else cwe_raw_id
                
                session.run("""
                    MERGE (w:Weakness {id: $id})
                    SET w.name = $name, w.description = $description, w.source = 'MITRE CWE'
                """, id=cwe_id, name=name, description=description)
                count += 1
        print(f"✨ {count} vulnerabilità CWE caricate come nodi 'Weakness'!")

    def ingest_capec(self, json_path):
        """Carica nodi Pattern e crea relazioni EXPLOITS verso Weakness."""
        print(f"🔍 Analisi file CAPEC e creazione relazioni...")
        with open(json_path, 'r') as f:
            capec_data = json.load(f)

        with self.driver.session() as session:
            count_patterns = 0
            count_rels = 0
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
                            elif source == 'cwe': related_cwes.append(ext_id)
                    
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
                        count_rels += 1
        print(f"✨ Caricati {count_patterns} Pattern e create {count_rels} relazioni 'EXPLOITS'!")

    def ingest_mitre(self, json_path):
        """Carica esclusivamente nodi Technique."""
        print(f"📖 Caricamento tecniche da {json_path}...")
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
        print(f"✨ Creati {count_tech} nodi Technique!")

    def ingest_opencre(self, json_path):
        """Carica i Requisiti e i legami VIOLATES dalle CWE."""
        print(f"📜 Ingestione OpenCRE: Collegamento vulnerabilità agli Standard...")
        with open(json_path, "r", encoding="utf-8") as f:
            opencre_data = json.load(f)

        with self.driver.session() as session:
            count_reqs = 0
            count_links = 0
            for cwe_id, mappings in opencre_data.items():
                clean_cwe = f"CWE-{cwe_id}" if not str(cwe_id).startswith("CWE-") else cwe_id
                for m in mappings:
                    req_id = f"{m['standard']}-{m['section']}"
                    # 1. Crea il nodo del Requisito
                    session.run("""
                        MERGE (r:Requirement {id: $req_id})
                        SET r.standard = $standard, r.section = $section, r.name = $cre_name
                    """, req_id=req_id, standard=m['standard'], section=m['section'], cre_name=m['cre_name'])
                    count_reqs += 1

                    # 2. Crea la relazione VIOLATES
                    res = session.run("""
                        MATCH (w:Weakness {id: $cwe_id})
                        MATCH (r:Requirement {id: $req_id})
                        MERGE (w)-[:VIOLATES]->(r)
                        RETURN count(r) as linked
                    """, cwe_id=clean_cwe, req_id=req_id).single()
                    
                    if res['linked'] > 0:
                        count_links += 1
        print(f"✨ Requisiti caricati: {count_reqs} | Collegamenti 'VIOLATES': {count_links}")

    def verify(self):
        """Verifica lo stato attuale del database."""
        print("\n📊 --- REPORT DI VERIFICA ---")
        query = """
        MATCH (n) RETURN labels(n)[0] as Etichetta, count(n) as Totale
        UNION ALL
        MATCH ()-[r]->() RETURN type(r) as Etichetta, count(r) as Totale
        """
        with self.driver.session() as session:
            res = session.run(query)
            for record in res:
                print(f"{record['Etichetta']:<15} | {record['Totale']}")

if __name__ == "__main__":
    URI = "bolt://10.0.2.2:7687"
    agent = KnowledgeIngestorAgent(URI, "neo4j", "***REMOVED***")
    try:
        # Eseguiamo i tre compiti core in sequenza
        agent.ingest_cwe('../data/cwe_list.csv')
        agent.ingest_capec('../data/capec.json')
        agent.ingest_mitre('../data/mitre.json')
        agent.ingest_opencre('../data/opencre_map.json')
        agent.verify()
    finally:
        agent.close()