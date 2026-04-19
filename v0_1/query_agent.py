from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma
from langchain_classic.chains import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate

# --- CONFIGURAZIONE ---
WINDOWS_IP = "10.0.2.2"
OLLAMA_URL = f"http://{WINDOWS_IP}:11434"
PERSIST_DIR = "./exploit_db_weights"
EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "mistral"

def run_query():
    # 1. Inizializzazione
    embeddings = OllamaEmbeddings(model=EMBED_MODEL, base_url=OLLAMA_URL)
    vectorstore = Chroma(persist_directory=PERSIST_DIR, embedding_function=embeddings)
    
    # 2. Configurazione LLM (Mistral su Windows)
    llm = ChatOllama(model=LLM_MODEL, base_url=OLLAMA_URL, temperature=0)

    # 3. Prompt Engineering
    system_prompt = (
        "Sei un assistente esperto in Cybersecurity e Penetration Testing.\n"
        "Usa i frammenti di contesto recuperati da Exploit-DB per rispondere.\n"
        "REGOLE:\n"
        "1. Se trovi l'exploit, descrivilo citando ID_EDB (es. 2030-00000), i dettagli tecnici e il link alla pagina correlata.\n"
        "2. Se il contesto non contiene l'exploit, devi dire che non lo hai trovato.\n"
        "3. Sii sintetico e professionale.\n\n"
        "CONTESTO:\n{context}"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
    ])

    # 4. Creazione Chain
    retriever = vectorstore.as_retriever(search_kwargs={"k": 20})
    combine_docs_chain = create_stuff_documents_chain(llm, prompt)
    rag_chain = create_retrieval_chain(retriever, combine_docs_chain)

    print("\n[!] Cyber-RAG Operativo. Digita 'exit' per uscire.")
    
    while True:
        user_input = input("\n🔍 Query: ")
        if user_input.lower() in ['exit', 'quit', 'q']: break

        # Prefisso obbligatorio per Nomic
        formatted_query = f"search_query: {user_input}"
        
        print("Analisi in corso...")
        response = rag_chain.invoke({"input": formatted_query})
        
        print("\n--- RISPOSTA DELL'AI ---")
        print(response["answer"])
        print("------------------------")

if __name__ == "__main__":
    run_query()