from hybrid_rag_agent import HybridRAGAnalystAgent

analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "ciaociao", "http://10.0.2.2:11434")

# Query di test: usa termini diversi da quelli presenti nel nome del nodo
query = "code execution through memory manipulation"

print(f"🔍 Testando la query: '{query}'")
# Cerchiamo tra le Weakness (CWE)
results = analyst.vector_tech.similarity_search_with_score(query, k=10)

for doc, score in results:
    print(f"-> [Score: {score:.4f}] ID: {doc.metadata['graph_id']} Name: {doc.metadata['name']}")