import re
from neo4j import GraphDatabase

class RelationalLinkerAgent:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def perform_normalization(self):
        """Pulisce e normalizza gli ID nel database per garantire il match numerico perfetto."""
        print("🧹 Fase 1: Normalizzazione ID (Vulnerability & Weakness)...")
        with self.driver.session() as session:
            session.run("""
                MATCH (v:Vulnerability) 
                WHERE v.cwe_id IS NOT NULL
                SET v.cwe_id = trim(replace(v.cwe_id, 'CWE-', ''))
            """)
            session.run("""
                MATCH (w:Weakness)
                SET w.id = trim(replace(w.id, 'CWE-', ''))
            """)
            print("  ✅ ID normalizzati in formato numerico puro.")

    def perform_mass_linking(self):
        """
        [CORREZIONE ARCHITETTONICA]
        Crea relazioni HAS_WEAKNESS tra Vulnerability e Weakness.
        """
        print("🔗 Fase 2: Creazione massiva relazioni HAS_WEAKNESS...")
        with self.driver.session() as session:
            result = session.run("""
                MATCH (v:Vulnerability), (w:Weakness)
                WHERE v.cwe_id = w.id
                MERGE (v)-[r:HAS_WEAKNESS]->(w)
                RETURN count(r) as count
            """)
            print(f"  ✨ Creati {result.single()['count']} collegamenti HAS_WEAKNESS!")

    def link_mitre_to_capec(self, csv_file):
        """
        Mappa Tecniche MITRE ai Pattern CAPEC in modo deterministico tramite CSV ufficiale.
        Questo è l'unico ponte valido tra l'azione offensiva e il difetto strutturale.
        """
        print(f"🕵️ Mappatura Technique -> Pattern (CSV: {csv_file})...")
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

    def verify(self):
        """Report finale dello stato delle relazioni nel grafo."""
        print("\n📊 --- REPORT DI VERIFICA RELAZIONI (GRAFO OTTIMIZZATO) ---")
        query = "MATCH ()-[r]->() RETURN type(r) as Tipo, count(r) as Totale"
        with self.driver.session() as session:
            res = session.run(query)
            for record in res:
                print(f"{record['Tipo']:<25} | {record['Totale']}")

if __name__ == "__main__":
    URI = "bolt://10.0.2.2:7687"
    linker = RelationalLinkerAgent(URI, "neo4j", "ciaociao")
    try:
        # Step 1: Normalizzazione e Linking Massivo
        linker.perform_normalization()
        linker.perform_mass_linking()
        
        # Step 2: Mapping deterministico MITRE -> CAPEC
        linker.link_mitre_to_capec('../data/658.csv')
        
        # Step 3: Verifica topologia
        linker.verify()
    finally:
        linker.close()