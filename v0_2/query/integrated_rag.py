import os
from PyPDF2 import PdfReader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

class CyberPredictiveIntegrator:
    def __init__(self, db_dir="../chroma_db", threshold=0.8):
        self.url = "http://10.0.2.2:11434"
        self.embeddings = OllamaEmbeddings(model="bge-m3", base_url=self.url)
        self.db = Chroma(persist_directory=db_dir, embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0.1)
        self.threshold = threshold

    def _smart_retrieval(self, text_segment):
        """
        Cerca sia CWE (debolezze) che MITRE (tecniche) per avere una visione completa.
        """
        # Cerchiamo i 5 pattern più vicini a quello che l'audit ha trovato
        results = self.db.similarity_search_with_score(text_segment, k=6)
        
        valid_context = []
        for doc, score in results:
            if score <= self.threshold:
                type_label = doc.metadata.get('type', 'N/A').upper()
                id_label = doc.metadata.get('id', 'N/A')
                valid_context.append(f"[{type_label}] {id_label}: {doc.page_content}")
        
        return "\n\n".join(valid_context)

    def analyze_security_report(self, file_path):
        """Analizza un report di audit o valutazione sicurezza."""
        print(f"📄 Analisi Audit Report: {file_path}")
        
        # Estrazione testo
        if file_path.endswith('.pdf'):
            reader = PdfReader(file_path)
            # Leggiamo tutto il report (se è un audit interno sarà di poche pagine)
            content = "\n".join([p.extract_text() for p in reader.pages])
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

        # RAG: Cerchiamo nel database i pattern corrispondenti ai problemi trovati nell'audit
        rag_evidence = self._smart_retrieval(content[:3000])
        
        # Prompt focalizzato sulla PROBABILITÀ e sul PATTERN d'attacco
        prompt = f"""
        [RUOLO: Senior Cyber Threat Intelligence Analyst]
        DOCUMENTO SOTTO ESAME: Security Audit Report.
        
        SINTOMI E DEBOLEZZE RILEVATE:
        {content[:4000]}
        
        EVIDENZE DAL DATABASE (CWE/MITRE):
        {rag_evidence if rag_evidence else "Nessuna corrispondenza specifica nel database."}
        
        OBIETTIVO DELL'ANALISI:
        1. RICONOSCIMENTO PATTERN: Quali pattern di attacco (MITRE) o debolezze (CWE) sono confermati?
        2. PROBABILITÀ DI ATTACCO: Basandoti sulla gravità delle falle (es. Log4j o credenziali default), stima la probabilità di un attacco imminente (Bassa, Media, Alta, Critica).
        3. SCENARIO PREVISTO: Descrivi come un attaccante sfrutterebbe questi pattern in sequenza (Kill Chain).
        4. PRIORITÀ DI INTERVENTO: Quale falla deve essere chiusa per prima per abbattere la probabilità di attacco?
        """
        return self.llm.invoke(prompt).content

if __name__ == "__main__":
    predictor = CyberPredictiveIntegrator()
    # Esegui il test su un file di audit specifico
    result = predictor.analyze_security_report("../audit_sicurezza.pdf")
    print("\n" + "="*50)
    print("🛡️ REPORT DI PREDIZIONE MINACCE")
    print("="*50)
    print(result)