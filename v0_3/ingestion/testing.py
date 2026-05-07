from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
URI = "bolt://10.0.2.2:7687"
USER = "neo4j"
PASSWORD = "ciaociao" # La tua password aggiornata

def run_global_test():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    
    with driver.session() as session:
        print("🔍 AVVIO TEST DI INTEGRITÀ DEL GRAFO CYBER...\n")

        # 1. Conteggio Nodi per Etichetta
        nodes_info = session.run("""
            MATCH (n)
            RETURN labels(n)[0] AS Label, count(n) AS Count
            ORDER BY Count DESC
        """).data()
        
        print("📊 DISTRIBUZIONE NODI:")
        for record in nodes_info:
            print(f"  • {record['Label']}: {record['Count']} nodi")

        # 2. Conteggio Relazioni per Tipo
        rels_info = session.run("""
            MATCH ()-[r]->()
            RETURN type(r) AS Type, count(r) AS Count
        """).data()
        
        print("\n🔗 DISTRIBUZIONE RELAZIONI:")
        if not rels_info:
            print("  ⚠️ Nessuna relazione trovata nel database!")
        for record in rels_info:
            print(f"  • {record['Type']}: {record['Count']} archi")

        # 3. Test della "Kill Chain" (Integrazione Totale)
        # Verifichiamo quante tecniche MITRE sono collegate fino alle CWE
        chain_count = session.run("""
            MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p:Pattern)-[:EXPLOITS]->(w:Weakness)
            RETURN count(DISTINCT t) AS TotalChains
        """).single()['TotalChains']
        
        print(f"\n🧠 CATENE DI CONOSCENZA COMPLETE (T->P->W): {chain_count}")

        # 4. Estrazione di un Campione Completo
        if chain_count > 0:
            print("\n🧪 ESEMPIO DI ANALISI STRUTTURATA:")
            sample = session.run("""
                MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p:Pattern)-[:EXPLOITS]->(w:Weakness)
                RETURN t.id AS MITRE, t.name AS Nome, p.id AS CAPEC, w.id AS CWE
                LIMIT 1
            """).single()
            
            print(f"  [!] Rilevata Tecnica: {sample['MITRE']} ({sample['Nome']})")
            print(f"      └── Si appoggia al Pattern: {sample['CAPEC']}")
            print(f"          └── Che sfrutta la vulnerabilità: {sample['CWE']}")
        else:
            print("\n❌ ERRORE: Il grafo è popolato ma i nodi sono isolati (mancano i collegamenti).")

    driver.close()

if __name__ == "__main__":
    run_global_test()