import gradio as gr
from hybrid_rag_agent import HybridRAGAnalystAgent
import re

# Configurazione connessioni
URI, OLLAMA_URL = "bolt://10.0.2.2:7687", "http://10.0.2.2:11434"
analyst = HybridRAGAnalystAgent(URI, "neo4j", "ciaociao", OLLAMA_URL)

def parse_report(report_text):
    """Scompone il report unico in 5 sezioni basate sui tag [TAG]."""
    sections = {
        "ANALISI": "Nessun dato.",
        "IDENTIFICATIVI": "Nessun dato.",
        "KILL_CHAIN": "Nessun dato.",
        "MITIGAZIONE": "Nessun dato.",
        "STANDARD": "Nessun dato."
    }
    
    # Regex per estrarre il contenuto tra i tag
    for key in sections.keys():
        pattern = rf"\[{key}\](.*?)(?=\[|$)"
        match = re.search(pattern, report_text, re.DOTALL)
        if match:
            sections[key] = match.group(1).strip()
            
    return (
        sections["ANALISI"], 
        sections["IDENTIFICATIVI"], 
        sections["KILL_CHAIN"], 
        sections["MITIGAZIONE"], 
        sections["STANDARD"]
    )

def run_ui_analysis(file_obj):
    if file_obj is None:
        return ["Carica un file!"] * 5
    
    # Esegui l'analisi originale
    report, _ = analyst.analyze_content(file_obj.name)
    
    # Dividi il report nelle sezioni per le schede
    return parse_report(report)

# --- CREAZIONE INTERFACCIA A SCHEDE ---
with gr.Blocks(theme=gr.themes.Soft(), title="CyberRAG Dashboard") as demo:
    gr.Markdown("# 🛡️ CyberRAG Intelligence Dashboard")
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(label="📂 Carica file sorgente")
            run_btn = gr.Button("🚀 ANALIZZA", variant="primary")
        
        with gr.Column(scale=3):
            # DEFINIZIONE DELLE SCHEDE (TABS)
            with gr.Tabs():
                with gr.TabItem("📝 ANALISI"):
                    out_analisi = gr.Markdown("Carica un file per visualizzare l'analisi.")
                
                with gr.TabItem("🆔 IDENTIFICATIVI"):
                    out_id = gr.Markdown("ID tecnici (CVE/CWE).")
                
                with gr.TabItem("⛓️ KILL CHAIN"):
                    out_kill = gr.Markdown("Percorso d'attacco ipotizzato.")
                
                with gr.TabItem("🛠️ MITIGAZIONE"):
                    out_mitig = gr.Markdown("Soluzioni consigliate.")
                
                with gr.TabItem("📜 STANDARD"):
                    out_std = gr.Markdown("Mappatura NIST/ISO.")

    gr.Markdown("--- \n *Sviluppato per Tesi di Laurea in Cyber Intelligence*")

    # Mappatura output: il bottone cliccato aggiorna tutte le 5 schede contemporaneamente
    run_btn.click(
        fn=run_ui_analysis,
        inputs=file_input,
        outputs=[out_analisi, out_id, out_kill, out_mitig, out_std]
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)