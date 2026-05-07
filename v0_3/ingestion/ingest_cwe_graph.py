import pandas as pd
from neo4j import GraphDatabase
import os

# --- CONFIGURAZIONE ---
CSV_FILE = '../data/cwe_list.csv'
URI = "bolt://10.0.2.2:7687" # IP Host dalla VM
USER = "neo4j"
PASSWORD = "ciaociao" 

def find_header_row(file_path):
    """Trova la riga di intestazione corretta nel CSV delle CWE."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if 'CWE-ID' in line and 'Name' in line:
                return i
    return 0

def ingest_cwe_graph():
    print("📊 Analisi file CWE e popolamento grafo...")
    header_idx = find_header_row(CSV_FILE)
    
    # Caricamento dati con pandas 
    df = pd.read_csv(CSV_FILE, low_memory=False, skiprows=header_idx)
    df.columns = [c.strip() for c in df.columns]

    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    
    with driver.session() as session:
        count = 0
        for index, row in df.iterrows():
            cwe_raw_id = str(index).strip() 
            name = str(row.get('CWE-ID', '')).strip()
            
            # Logica di pulizia nomi 
            if name.lower() in ['base', 'variant', 'class', 'nan']:
                name = str(row.get('Name', 'Unknown Weakness')).strip()

            description = str(row.get('Description', '')).strip()
            
            if not cwe_raw_id or cwe_raw_id.lower() in ['nan', 'cwe-id'] or not description or description.lower() == 'nan':
                continue

            cwe_id = f"CWE-{cwe_raw_id}" if "CWE" not in cwe_raw_id.upper() else cwe_raw_id
            
            # QUERY CYPHER: Crea il nodo se non esiste (MERGE)
            query = """
            MERGE (w:Weakness {id: $id})
            SET w.name = $name,
                w.description = $description,
                w.source = 'MITRE CWE'
            """
            session.run(query, id=cwe_id, name=name, description=description)
            count += 1
            
    driver.close()
    print(f"✨ {count} vulnerabilità CWE caricate come nodi 'Weakness'!")

if __name__ == "__main__":
    ingest_cwe_graph()