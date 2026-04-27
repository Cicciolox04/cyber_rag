from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser

# --- CONFIGURAZIONE ---
DB_DIR = '../chroma_db'
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
retriever = vector_db.as_retriever(search_kwargs={"k": 5})

# Modello
llm = ChatOllama(model="mistral", base_url="http://10.0.2.2:11434", temperature=0.1)

# --- PROMPT DESIGN (Fondamentale per la Tesi) ---
template = """Sei un assistente AI esperto in Cyber Security. 
Usa il contesto fornito (MITRE ATT&CK e CWE) per rispondere alla domanda.
Se non trovi la risposta nel contesto, ammettilo. Sii tecnico e preciso.

CONTESTO:
{context}

DOMANDA: 
{question}

RISPOSTA (Includi ID tecnici):"""

prompt = ChatPromptTemplate.from_template(template)

# --- COSTRUZIONE DELLA CATENA (LCEL) ---
# Questa struttura è perfetta da spiegare nel capitolo "Architettura del Sistema"
rag_chain = (
    {"context": retriever, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)

def ask_expert(question):
    print(f"\n" + "="*60)
    print(f"👨‍💻 ANALISTA: {question}")
    print("="*60)
    
    # Esecuzione
    response = rag_chain.invoke(question)
    
    print(f"\n🤖 SISTEMA RAG:\n{response}")

# Test di correlazione
ask_expert("Analizza questa riga di log e identifica il pattern cyber:"
" 2026-04-27 10:45:12 GET /admin.php?cmd=whoami&debug=true HTTP/1.1 200 1540"
"\nQuale tecnica MITRE è in atto e quale vulnerabilità CWE la permette?")