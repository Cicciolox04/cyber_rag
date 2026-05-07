import re
from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
CSV_FILE = '../data/658.csv'
URI = "bolt://10.0.2.2:7687"
AUTH = ("neo4j", "ciaociao")

def ingest_capec_csv_mappings():
    driver = GraphDatabase.driver(URI, auth=AUTH)
    count_links = 0
    
    # Regex per ID CAPEC a inizio riga
    re_capec_id = re.compile(r'^"?(\d+),')
    
    # Regex per ID ATT&CK nel testo (cerca ENTRY ID:XXXX)
    re_attack_id = re.compile(r'TAXONOMY NAME:ATTACK:ENTRY ID:([\d\.]+)')

    print(f"🕵️ Scansione testuale di {CSV_FILE} per creazione relazioni...")

    with driver.session() as session:
        with open(CSV_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # 1. Identifica il Pattern CAPEC nella riga
                capec_match = re_capec_id.search(line)
                if not capec_match:
                    continue
                
                capec_id = f"CAPEC-{capec_match.group(1)}"
                
                # 2. Cerca riferimenti a tecniche MITRE
                attack_matches = re_attack_id.findall(line)
                
                for t_num in set(attack_matches):
                    # Normalizza l'ID (es. 1059 -> T1059)
                    t_id = f"T{t_num}" if not t_num.startswith('T') else t_num
                    
                    # Crea la relazione se entrambi i nodi esistono
                    res = session.run("""
                        MATCH (t:Technique {id: $tid})
                        MATCH (p:Pattern {id: $pid})
                        MERGE (t)-[:MAPS_TO_PATTERN]->(p)
                        RETURN count(p) as f
                    """, tid=t_id, pid=capec_id).single()
                    
                    if res and res['f'] > 0:
                        count_links += 1

    driver.close()
    print(f"✨ Relazioni MAPS_TO_PATTERN create: {count_links}!")

if __name__ == "__main__":
    ingest_capec_csv_mappings()