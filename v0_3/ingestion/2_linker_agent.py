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

    def link_vulnerability_to_weakness(self):
        """
        Collega CVE (Vulnerability) a CWE (Weakness).
        Utile se hai importato le CVE con l'attributo cwe_id.
        """
        print("🔗 Agente Linker: Collegamento Vulnerability (CVE) -> Weakness (CWE)...")
        query = """
        MATCH (v:Vulnerability)
        WHERE v.cwe_id IS NOT NULL
        MATCH (w:Weakness {id: v.cwe_id})
        MERGE (v)-[r:INSTANCE_OF]->(w)
        RETURN count(r) as count
        """
        with self.driver.session() as session:
            res = session.run(query).single()
            print(f"   -> Creati {res['count']} collegamenti INSTANCE_OF")

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
        """Genera scorciatoie logiche per l'analisi RAG."""
        print("🧠 Agente Linker: Generazione Ponti di Analisi e Compliance...")
        with self.driver.session() as session:
            # 1. Technique -> Weakness (via CAPEC)
            res_a = session.run("""
                MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p:Pattern)-[:EXPLOITS]->(w:Weakness)
                MERGE (t)-[r:HAS_WEAKNESS]->(w)
                RETURN count(r) as count
            """).single()
            
            # 2. Technique -> Requirement (Ponte Compliance)
            res_b = session.run("""
                MATCH (t:Technique)-[:HAS_WEAKNESS]->(w:Weakness)-[:VIOLATES]->(r:Requirement)
                MERGE (t)-[v:INFERRED_COMPLIANCE]->(r)
                RETURN count(v) as count
            """).single()

            # 3. Exploit -> Requirement (Scorciatoia di Pericolo Reale)
            # Se esiste un exploit per una CVE che porta a un Requisito violato
            res_c = session.run("""
                MATCH (e:Exploit)-[:EXPLOITS_VULNERABILITY]->(v:Vulnerability)-[:INSTANCE_OF]->(w:Weakness)-[:VIOLATES]->(r:Requirement)
                MERGE (e)-[rel:DIRECTLY_THREATENS]->(r)
                RETURN count(rel) as count
            """).single()
            
            # 4. Technique -> Exploit (Collega MITRE a Kali Exploit-DB)
            res_d = session.run("""
                MATCH (t:Technique)-[:HAS_WEAKNESS]->(w:Weakness)<-[:INSTANCE_OF]-(v:Vulnerability)<-[:EXPLOITS_VULNERABILITY]-(e:Exploit)
                MERGE (t)-[rel:HAS_ACTIVE_EXPLOIT]->(e)
                RETURN count(rel) as count
            """).single()
            
            print(f"   -> Nuove relazioni HAS_WEAKNESS: {res_a['count']}")
            print(f"   -> Ponti INFERRED_COMPLIANCE: {res_b['count']}")
            print(f"   -> Requisiti minacciati da exploit reali: {res_c['count']}")
            print(f"   -> Tecniche con exploit pronti su Kali: {res_d['count']}")

    def verify(self):
        print("\n📊 --- REPORT DI VERIFICA RELAZIONI ---")
        query = "MATCH ()-[r]->() RETURN type(r) as Tipo, count(r) as Totale"
        with self.driver.session() as session:
            res = session.run(query)
            for record in res:
                print(f"{record['Tipo']:<25} | {record['Totale']}")

if __name__ == "__main__":
    URI = "bolt://10.0.2.2:7687"
    linker = RelationalLinkerAgent(URI, "neo4j", "ciaociao")
    try:
        # 1. Mapping standard
        linker.link_mitre_to_capec('../data/658.csv')
        
        # 2. Collegamenti Vulnerabilità (Assicurati di aver popolato le CVE)
        linker.link_vulnerability_to_weakness()
        
        # 3. Estrazione Regex e Inferenze pesanti
        linker.link_mitre_to_cwe_regex()
        linker.run_inferences()
        
        linker.verify()
    finally:
        linker.close()