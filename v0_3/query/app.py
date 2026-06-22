import gradio as gr
from hybrid_rag_agent import HybridRAGAnalystAgent
import re

# Configurazione connessioni
URI, OLLAMA_URL = "bolt://10.0.2.2:7687", "http://10.0.2.2:11434"
analyst = HybridRAGAnalystAgent(URI, "neo4j", "ciaociao", OLLAMA_URL)

def parse_report(report_text):
    """Scompone il report in modo dinamico e robusto, tollerando variazioni di Llama3."""
    import re
    
    sections = {
        "ANALISI": "Nessun dato.",
        "IDENTIFICATIVI": "Nessun dato.",
        "KILL_CHAIN": "Nessun dato.",
        "STANDARD": "Nessun dato.",
        "MITIGAZIONE": "Nessun dato.",
    }
    
    # Regex flessibili che intercettano varianti come: ### Analisi, **[ANALISI]**, Analisi:, ecc.
    patterns = {
        "ANALISI": r"(?:\[|\*\*|###|\b)ANALISI(?:\b|\]|\*\*|:)",
        "IDENTIFICATIVI": r"(?:\[|\*\*|###|\b)IDENTIFICATIVI(?:\b|\]|\*\*|:)",
        "KILL_CHAIN": r"(?:\[|\*\*|###|\b)KILL[\s_]CHAIN(?:\b|\]|\*\*|:)",
        "STANDARD": r"(?:\[|\*\*|###|\b)STANDARD(?:\b|\]|\*\*|:)",
        "MITIGAZIONE": r"(?:\[|\*\*|###|\b)MITIGAZIONE(?:\b|\]|\*\*|:)"
    }
    
    # Identifichiamo la posizione di inizio di ogni sezione trovata nel testo
    found_sections = []
    for key, pat in patterns.items():
        match = re.search(pat, report_text, re.IGNORECASE) # Diventa case-insensitive
        if match:
            found_sections.append((key, match.start(), match.end()))
    
    # Ordiniamo le sezioni in base alla loro apparizione cronologica nel testo del report
    found_sections.sort(key=lambda x: x[1])
    
    # Estraiamo il testo compreso tra la fine di una sezione e l'inizio della successiva
    for i, (key, start, end) in enumerate(found_sections):
        next_start = found_sections[i+1][1] if i + 1 < len(found_sections) else len(report_text)
        content = report_text[end:next_start].strip()
        
        # Pulisce eventuali residui iniziali di formattazione lasciati dal modello (es. due punti, trattini o spazi vuoti)
        content = re.sub(r'^[:\s\*-]+', '', content).strip()
        sections[key] = content
            
    # L'ordine di ritorno deve combaciare esattamente con la lista passata a Gradio:
    # outputs=[out_analisi, out_id, out_kill, out_mitig, out_std]
    return (
        sections["ANALISI"],        # Associato a out_analisi
        sections["IDENTIFICATIVI"],  # Associato a out_id
        sections["KILL_CHAIN"],      # Associato a out_kill
        sections["STANDARD"],        # Associato a out_std   (corretto l'ordine)
        sections["MITIGAZIONE"],     # Associato a out_mitig (corretto l'ordine)
    )

def run_ui_analysis(file_obj):
    if file_obj is None:
        return ["Carica un file!"] * 5
    
    try:
        # Assicuriamoci di estrarre il percorso correttamente
        file_path = file_obj if isinstance(file_obj, str) else file_obj.name
        print(f"\n📥 UI: Ricevuto file per l'analisi: {file_path}")
        
        # Esegui l'analisi originale
        report, _ = analyst.analyze_content(file_path)
        
        # Dividi il report nelle sezioni per le schede
        print("✂️ UI: Smistamento del report nelle schede completato.")
        return parse_report(report)
    
    except Exception as e:
        import traceback
        errore_dettagliato = traceback.format_exc()
        print(f"❌ ERRORE IMPREVISTO IN GRADIO:\n{errore_dettagliato}")
        # Mostriamo l'errore in tutte le schede così è impossibile non notarlo
        return [f"⚠️ Si è verificato un errore: {str(e)}"] * 5

# --- CREAZIONE INTERFACCIA A SCHEDE ---

stile_css = """
.prose {
    font-size: 1.15rem !important; 
    line-height: 1.6 !important;
}
.tabitem {
    font-size: 1.1rem !important;
}
"""

with gr.Blocks(theme=gr.themes.Soft(),css=stile_css, title="CyberRAG Dashboard") as demo:
    gr.Markdown("# 🛡️ CyberRAG Dashboard")
    
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
                
                with gr.TabItem("📜 STANDARD"):
                    out_std = gr.Markdown("Mappatura NIST/ISO.")

                with gr.TabItem("🛠️ MITIGAZIONE"):
                    out_mitig = gr.Markdown("Soluzioni consigliate.")
                

    gr.Markdown("--- \n *Sviluppato per Tesi di Laurea in Sicurezza Informatica*")

    # Mappatura output: il bottone cliccato aggiorna tutte le 5 schede contemporaneamente
    run_btn.click(
        fn=run_ui_analysis,
        inputs=file_input,
        outputs=[out_analisi, out_id, out_kill, out_std, out_mitig]
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)