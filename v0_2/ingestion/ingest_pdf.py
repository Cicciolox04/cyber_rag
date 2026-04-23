import os
from PyPDF2 import PdfReader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from langchain_core.documents import Document
from tqdm import tqdm

# --- CONFIGURAZIONE ---
PDF_FILE = "../report.pdf"
DB_DIR = "../chroma_db"
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")

def ingest_pdf():
    print(f"📖 Lettura di {PDF_FILE}...")
    reader = PdfReader(PDF_FILE)
    full_text = ""
    for page in reader.pages:
        text = page.extract_text()
        if text:
            full_text += text + "\n"

    # 1. CHUNKING: Dividiamo il testo in pezzi gestibili
    # Usiamo RecursiveCharacterTextSplitter perché "capisce" i paragrafi
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1500,
        chunk_overlap=200,
        length_function=len
    )
    chunks = text_splitter.split_text(full_text)
    print(f"✂️ Testo diviso in {len(chunks)} frammenti.")

    # 2. CREAZIONE DOCUMENTI
    documents = []
    for i, chunk in enumerate(chunks):
        doc = Document(
            page_content=chunk,
            metadata={
                "source": PDF_FILE,
                "type": "threat-report",
                "chunk_id": i
            }
        )
        documents.append(doc)

    # 3. CARICAMENTO NEL DB
    print(f"🚀 Inserimento di {len(documents)} frammenti in ChromaDB...")
    db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
    
    # Inseriamo a piccoli lotti per non sovraccaricare il sistema
    batch_size = 50
    for i in tqdm(range(0, len(documents), batch_size)):
        db.add_documents(documents[i : i + batch_size])

    print("\n✅ Ingestione completata! Il report è ora parte della base di conoscenza.")

if __name__ == "__main__":
    ingest_pdf()