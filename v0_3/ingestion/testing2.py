from neo4j import GraphDatabase

# --- CONFIGURAZIONE ---
URI = "bolt://10.0.2.2:7687"
AUTH = ("neo4j", "***REMOVED***")

def run_test():
    driver = GraphDatabase.driver(URI, auth=AUTH)
    with driver.session() as session:
        print("🔍 --- AVVIO TESTING GUIDATO --- 🔍\n")

        # TEST 1: Integrità Quantitativa
        print("📊 [1] VERIFICA QUANTITATIVA")
        counts = session.run("""
            MATCH (n)
            RETURN labels(n)[0] as Label, count(n) as Count
        """).data()
        for item in counts:
            print(f"  • {item['Label']}: {item['Count']} nodi")
        
        rels = session.run("""
            MATCH ()-[r]->()
            RETURN type(r) as Type, count(r) as Count
        """).data()
        for item in rels:
            print(f"  • {item['Type']}: {item['Count']} archi")

        # TEST 2: Deep Traversal (La Prova del Nove)
        print("\n🧬 [2] TEST DI TRAVERSATA PROFONDA (T -> P -> W -> R)")
        # Proviamo a tracciare una tecnica simbolo: T1059 (Command and Scripting Interpreter)
        path_test = session.run("""
            MATCH (t:Technique)-[:MAPS_TO_PATTERN]->(p:Pattern)-[:EXPLOITS]->(w:Weakness)-[:VIOLATES]->(r:Requirement)
            RETURN t.id as T, p.id as P, w.id as W, r.standard as S, r.section as Sec
            LIMIT 1
        """).single()

        if path_test:
            print(f"  ✅ SUCCESS: Trovata catena completa!")
            print(f"     {path_test['T']} ➔ {path_test['P']} ➔ {path_test['W']} ➔ {path_test['S']} (Sez. {path_test['Sec']})")
        else:
            print("  ⚠️ WARNING: Nessuna catena completa T->P->W->R trovata. Verificare mapping OpenCRE.")

        # TEST 3: Analisi della Copertura (Gap Analysis)
        print("\n📉 [3] ANALISI DELLA COPERTURA (COMPLIANCE GAP)")
        gap = session.run("""
            MATCH (t:Technique)
            OPTIONAL MATCH (t)-[:MAPS_TO_PATTERN]->(p)-[:EXPLOITS]->(w)-[:VIOLATES]->(r)
            WITH t, count(r) as c_links
            RETURN 
                CASE WHEN c_links > 0 THEN 'Coperta' ELSE 'Isolata' END as Stato,
                count(t) as Numero,
                round(count(t) * 100.0 / 823, 2) as Percentuale
        """).data()
        
        for g in gap:
            color = "🟢" if g['Stato'] == 'Coperta' else "🔴"
            print(f"  {color} {g['Stato']}: {g['Numero']} tecniche ({g['Percentuale']}%)")

    driver.close()

if __name__ == "__main__":
    run_test()