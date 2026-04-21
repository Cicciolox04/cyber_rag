from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma

class CyberThesisEngineV3:
    def __init__(self, threshold=0.8):
        self.embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
        self.db = Chroma(persist_directory="../chroma_db", embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url="http://10.0.2.2:11434", temperature=0)
        self.threshold = threshold # Soglia di accettazione

    def get_scored_context(self, query, filter_type, k=5):
        # Utilizziamo similarity_search_with_score
        results = self.db.similarity_search_with_score(
            query, 
            k=k, 
            filter={"type": filter_type}
        )

        valid_docs = []
        for doc, score in results:
            # NOTA: Per la distanza L2 di Chroma, più basso è lo score, meglio è.
            # Se lo score è > threshold, il documento è considerato irrilevante.
            if score <= self.threshold:
                valid_docs.append(doc)
                print(f"✅ [MATCH] {doc.metadata.get('id')} - Score: {score:.4f}")
            else:
                print(f"❌ [SCARTATO] {doc.metadata.get('id')} - Score: {score:.4f} (Troppo alto)")
        
        return valid_docs

    def analyze(self, file_path):
        with open(file_path, 'r') as f:
            code = f.read()

        # 1. Recupero CWE filtrate
        cwe_docs = self.get_scored_context(code, "vulnerability")
        
        if not cwe_docs:
            return "Nessun pattern di vulnerabilità riconosciuto con sufficiente confidenza."

        cwe_context = "\n".join([d.page_content for d in cwe_docs])

        # 2. Recupero ATT&CK filtrate
        attack_docs = self.get_scored_context(cwe_context, "attack-pattern")
        attack_context = "\n".join([d.page_content for d in attack_docs])

        # 3. Analisi Finale (solo se abbiamo dati di qualità)
        prompt = f"""
        [ANALISI TECNICA PER TESI]
        CODICE SORGENTE: {code}
        
        CONTESTO VULNERABILITÀ (CWE): {cwe_context}
        CONTESTO ATTACCO (MITRE): {attack_context}

        Compito:
        1. Identifica la funzione insicura nel codice e associala a una CWE.
        2. Spiega come un attaccante sfrutta questa falla (Fase: Exploitation).
        3. PREDICI la mossa successiva nella Cyber Kill Chain (es. Installation o C2) basandoti sui pattern MITRE.
        """
        
        return self.llm.invoke(prompt).content

engine = CyberThesisEngineV3()
print(engine.analyze("../vulnerable/hardcoded_creds.py"))