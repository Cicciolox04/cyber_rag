import os
from PyPDF2 import PdfReader

def test_extraction(file_path):
    print(f"--- Analisi file: {os.path.basename(file_path)} ---")
    ext = os.path.splitext(file_path)[1].lower()
    content = ""

    if ext == ".pdf":
        reader = PdfReader(file_path)
        print(f"Pagine trovate: {len(reader.pages)}")
        for i, page in enumerate(reader.pages):
            text = page.extract_text()
            if text:
                content += f"\n[PAGINA {i+1}]\n{text}"
    else:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    # Mostriamo i primi 1000 caratteri e gli ultimi 500 per verifica
    print("\n--- Anteprima Contenuto Estratto ---")
    print(content[:1000]) 
    print("\n[...]\n")
    print(content[-500:])
    print("\n--- Fine Estrazione ---\n")
    return content

# TEST VELOCE
test_extraction("report.pdf")