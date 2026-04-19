import os
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma

class CyberThesisEngineV3:
    def __init__(self, threshold=0.7):
        self.url = "http://10.0.2.2:11434"
        self.embeddings = OllamaEmbeddings(model="mistral", base_url=self.url)
        self.db = Chroma(persist_directory="./chroma_db", embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0)
        self.threshold = threshold
        
        # Parole chiave critiche per il Boosting
        self.security_keywords = [
            "password", "secret", "token", "key", "admin", "login", # Credenziali
            "strcpy", "buffer", "overflow", "memcpy", "gets",      # Memoria
            "system", "exec", "popen", "sprintf", "cmd"            # Injection
        ]

    def hybrid_search(self, query, filter_type, k=20):
        # 1. Identifichiamo quali keyword sono presenti nell'input dell'utente
        found_keywords = [w for w in self.security_keywords if w in query.lower()]
        
        # 2. Recuperiamo un set più ampio di candidati (k=20)
        results = self.db.similarity_search_with_score(
            query, k=k, filter={"type": filter_type}
        )

        valid_docs = []
        print(f"\n--- Analisi Similarità ({filter_type}) ---")
        
        for doc, raw_score in results:
            # 3. Logica di Boosting: se il documento contiene la keyword, 
            # abbassiamo lo score (rendendolo più "vicino")
            boost = 0
            for kw in found_keywords:
                if kw in doc.page_content.lower():
                    boost += 0.4 # Bonus di confidenza
            
            final_score = raw_score - boost
            
            if final_score <= self.threshold:
                valid_docs.append(doc)
                status = "🔥 BOOSTED" if boost > 0 else "✅ OK"
                print(f"{status} {doc.metadata.get('id')} - Score Finale: {final_score:.4f} (Originale: {raw_score:.4f})")
        
        return valid_docs

    def analyze(self, file_path):
        with open(file_path, 'r') as f:
            code = f.read()

        # Step 1: Ricerca CWE con Boosting
        cwe_docs = self.hybrid_search(code, "vulnerability")
        if not cwe_docs:
            return "Nessun pattern vulnerabile rilevato con sufficiente confidenza."

        cwe_context = "\n".join([d.page_content for d in cwe_docs])

        # Step 2: Ricerca ATT&CK correlata
        attack_docs = self.hybrid_search(cwe_context, "attack-pattern")
        attack_context = "\n".join([d.page_content for d in attack_docs])

        # Step 3: Generazione Report
        prompt = f"""
        Sei un esperto di Cyber Intelligence. Analizza il codice e i pattern trovati.
        CODICE: {code}
        VULNERABILITA' (CWE): {cwe_context}
        TECNICHE (ATT&CK): {attack_context}

        Compito: Produci un report che colleghi la falla nel codice alla prossima mossa nella Kill Chain.
        """
        return self.llm.invoke(prompt).content

# Test
engine = CyberThesisEngineV3(threshold=0.8) # Soglia leggermente più permissiva per il boosting
print(engine.analyze("hardcoded_creds.py"))