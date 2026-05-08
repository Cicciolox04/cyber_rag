import re
from neo4j import GraphDatabase

class RelationalLinkerAgent:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def link_mitre_to_capec(self, csv_file):
        """Mappa Tecniche a Pattern CAPEC."""
        print(f"🕵️ Agente Linker: Mappatura Technique -> Pattern (CSV: {csv_file})...")
        re_capec_id = re.compile(r'^"?(\d+),')
        re_attack_id = re.compile(r'TAXONOMY NAME:ATTACK:ENTRY ID:([\d\.]+)')
        
        with self.driver.session() as session:
            count = 0
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    capec_match = re_capec_id.search(line)
                    if capec_match:
                        capec_id = f"CAPEC-{capec_match.group(1)}"
                        attack_matches = re_attack_id.findall(line)
                        for t_num in set(attack_matches):
                            t_id = f"T{t_num}" if not t_num.startswith('T') else t_num
                            res = session.run("""
                                MATCH (t:Technique {id: $tid}), (p:Pattern {id: $pid})
                                MERGE (t)-[r:MAPS_TO_PATTERN]->(p)
                                RETURN count(r) as f
                            """, tid=t_id, pid=capec_id).single()
                            if res['f'] > 0: count += 1
        print(f"✨ Relazioni MAPS_TO_PATTERN create: {count}")

    def link_mitre_to_cwe_regex(self):
        """Estrae legami diretti Technique -> Weakness dalle descrizioni."""
        print("🔎 Agente Linker: Scansione descrizioni MITRE per estrazione CWE...")
        re_cwe = re.compile(r"CWE-(\d+)", re.IGNORECASE)
        
        with self.driver.session() as session:
            techniques = session.run("MATCH (t:Technique) WHERE t.description IS NOT NULL RETURN t.id as id, t.description as desc").data()
            count = 0
            for tech in techniques:
                found_cwes = re_cwe.findall(tech['desc'])
                for cwe_num in set(found_cwes):
                    cwe_id = f"CWE-{cwe_num}"
                    res = session.run("""
                        MATCH (t:Technique {id: $tid}), (w:Weakness {id: $wid})
                        MERGE (t)-[r:HAS_WEAKNESS]->(w)
                        RETURN count(r) as f
                    """, tid=tech['id'], wid=cwe_id).single()
                    if res['f'] > 0: count += 1
        print(f"✨ Archi HAS_WEAKNESS (Regex) creati: {count}")

    def run_inferences(self):
        print("🧠 Agente Linker: Generazione Ponti di Compliance...")
        with self.driver.session() as session:
            # Crea HAS_WEAKNESS basandosi sulla catena Technique -> Pattern -> Weakness
            res_a = session.run("""
                MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p:Pattern)-[:EXPLOITS]->(w:Weakness)
                MERGE (t)-[r:HAS_WEAKNESS]->(w)
                RETURN count(r) as count
            """).single()
            
            # Crea INFERRED_COMPLIANCE basandosi sulla catena Technique -> Weakness -> Requirement
            res_b = session.run("""
                MATCH (t:Technique)-[:HAS_WEAKNESS]->(w:Weakness)-[:VIOLATES]->(r:Requirement)
                MERGE (t)-[v:INFERRED_COMPLIANCE]->(r)
                RETURN count(v) as count
            """).single()
            
            print(f"   -> Nuove relazioni HAS_WEAKNESS: {res_a['count']}")
            print(f"   -> Ponti INFERRED_COMPLIANCE creati: {res_b['count']}")

    def verify(self):
        print("\n📊 --- REPORT DI VERIFICA RELAZIONI ---")
        query = "MATCH ()-[r]->() RETURN type(r) as Tipo, count(r) as Totale"
        with self.driver.session() as session:
            res = session.run(query)
            for record in res:
                print(f"{record['Tipo']:<20} | {record['Totale']}")

if __name__ == "__main__":
    URI = "bolt://10.0.2.2:7687"
    linker = RelationalLinkerAgent(URI, "neo4j", "ciaociao")
    try:
        linker.link_mitre_to_capec('../data/658.csv')
        linker.link_mitre_to_cwe_regex()
        linker.run_inferences()
        linker.verify()
    finally:
        linker.close()