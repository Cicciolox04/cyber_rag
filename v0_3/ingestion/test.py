import pandas as pd

def inspect_csv(file_path):
    print(f"--- Ispezione file: {file_path} ---")
    
    # Leggiamo le prime 5 righe grezze per vedere i metadati del MITRE
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        print("\n📄 Prime 3 righe del file (Grezze):")
        for i in range(3):
            print(f"Linea {i}: {f.readline().strip()}")

    # Cerchiamo l'intestazione corretta
    try:
        # Cerchiamo la riga che contiene le colonne reali
        header_row = 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if 'CWE-ID' in line and 'Name' in line:
                    header_row = i
                    break
        
        df = pd.read_csv(file_path, skiprows=header_row, low_memory=False)
        print(f"\n✅ Intestazione trovata alla riga: {header_row}")
        print(f"📊 Colonne rilevate: {df.columns.tolist()}")
        print(f"🔢 Totale righe nel file: {len(df)}")
        
        # Vediamo i primi 5 ID per capire il formato
        print("\n🆔 Primi 5 valori della colonna 'CWE-ID':")
        print(df['CWE-ID'].head().tolist())
        
        # Cerchiamo la CWE-918 come test
        ssrf = df[df['CWE-ID'].astype(str).str.contains('918', na=False)]
        print(f"\n🔍 Ricerca CWE-918 (SSRF): {'TROVATA' if not ssrf.empty else 'NON TROVATA'}")
        
    except Exception as e:
        print(f"\n❌ Errore durante l'ispezione: {e}")

if __name__ == "__main__":
    inspect_csv('../data/cwe_list.csv')