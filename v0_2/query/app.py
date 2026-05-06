import gradio as gr
import os
from app_demo_tesi import CyberPredictiveIntegrator

# --- INIZIALIZZAZIONE BACKEND ---
db_status = "Inizializzazione..."
db_path_display = "N/D"

try:
    predictor = CyberPredictiveIntegrator()
    db_path_display = predictor.db_dir
    # Conteggio documenti per verificare se il DB è letto correttamente
    count = predictor.db._collection.count()
    db_status = f"✅ Collegato ({count} documenti)"
except Exception as e:
    predictor = None
    db_status = f"❌ Errore: {e}"

def run_ui(files, folder, progress=gr.Progress(track_tqdm=True)):
    if predictor is None:
        return "Backend non pronto.", "", "", "", ""
    
    all_files = []
    if files: all_files.extend(files)
    if folder: all_files.extend(folder)
    
    if not all_files:
        return "⚠️ Nessun file caricato.", "", "", "", ""
    
    try:
        # FASE 1: Lettura dati
        progress(0.2, desc="📖 Lettura file in corso...")
        
        # FASE 2: Analisi RAG e LLM
        progress(0.5, desc="🔍 Interrogazione DB e generazione analisi...")
        sections, ids = predictor.analyze_security_report(all_files)
        
        # FASE 3: Formattazione
        progress(0.9, desc="✨ Elaborazione finale...")
        ids_formatted = "\n".join([f"• {i}" for i in ids]) if ids else "Nessun ID trovato."
        
        return (
            sections.get("PATTERN", "N/D"), 
            sections.get("IDENTIFICATIVI", "N/D"), 
            sections.get("CONFORMITA", "N/D"), 
            sections.get("MITIGAZIONE", "N/D"),
            ids_formatted
        )
    except Exception as e:
        return f"❌ Errore durante l'analisi: {e}", "", "", "", ""

# --- LAYOUT UI ---
with gr.Blocks(title="Cyber Security Analysis") as demo:
    gr.Markdown("# 🛡️ Cyber Security Analysis Dashboard")
    
    # Pannello Informativo Database
    with gr.Row():
        gr.Textbox(value=db_status, label="Stato Database Vettoriale", interactive=False)
        gr.Textbox(value=db_path_display, label="Percorso Cartella DB", interactive=False)

    with gr.Row():
        # Colonna Upload
        with gr.Column(scale=1):
            f_in = gr.File(label="📄 Carica File (Singoli o Multipli)", file_count="multiple")
            d_in = gr.File(label="📂 Carica Intera Cartella", file_count="directory")
            run_btn = gr.Button("🚀 AVVIA ANALISI", variant="primary")
            
        # Colonna Risultati
        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.TabItem("🧩 Pattern & Analisi"):
                    out_p = gr.Markdown("Carica i dati per visualizzare l'analisi dei pattern.")
                with gr.TabItem("🆔 Identificativi"):
                    out_i = gr.Markdown()
                with gr.TabItem("📜 Conformità OpenCRE"):
                    out_c = gr.Markdown()
                with gr.TabItem("🛠️ Mitigazione"):
                    out_m = gr.Markdown()
                with gr.TabItem("📚 Sorgenti RAG"):
                    out_d = gr.Code(label="ID estratti dal DB vettoriale")

    # Collegamento click con barra di progresso
    run_btn.click(
        fn=run_ui, 
        inputs=[f_in, d_in], 
        outputs=[out_p, out_i, out_c, out_m, out_d]
    )

if __name__ == "__main__":
    # Configurazione Gradio 6.0: tema e server inclusi nel launch
    demo.launch(
        server_name="0.0.0.0", 
        server_port=7860,
        theme=gr.themes.Soft()
    )