import gradio as gr
import os
from query.app_demo_tesi import CyberPredictiveIntegrator

integrator = CyberPredictiveIntegrator()

def process_combined(folder_data, files_data, progress=gr.Progress()):
    # Decidiamo quale input usare (priorità alla cartella se entrambi presenti)
    input_data = folder_data if folder_data else files_data
    
    if not input_data:
        return ["⚠️ Nessun file o cartella selezionata"] + [""] * 5

    progress(0.1, desc="Preparazione...")
    progress(0.5, desc="Analisi in corso...")
    
    data, raw_ids = integrator.analyze_security_report(input_data)
    
    if not data:
        return ["❌ Errore nella lettura"] + [""] * 5

    progress(1.0, desc="Analisi completata!")
    return (
        "✅ Analisi Terminata",
        data['pattern'],
        data['killchain'],
        data['ids'],
        data['conformita'],
        data['mitigazione']
    )

with gr.Blocks(title="Cyber Tesi UI") as demo:
    gr.Markdown("# 🛡️ Sistema di Analisi Predittiva")
    
    with gr.Row():
        with gr.Column(scale=1):
            # Due componenti separati per risolvere il limite del browser
            folder_input = gr.File(label="📂 Carica Intera Cartella", file_count="directory")
            file_input = gr.File(label="📄 Carica File Singoli", file_count="multiple")
            
            with gr.Row():
                run_btn = gr.Button("🚀 AVVIA ANALISI", variant="primary", interactive=False)
                stop_btn = gr.Button("⏹️ STOP", variant="stop")
            
            status = gr.Label(value="In attesa", label="Stato")

        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.TabItem("🧩 Pattern & KillChain"):
                    out_pattern = gr.Markdown(label="Pattern Recognition")
                    gr.Markdown("---") # Sostituto compatibile di Separator
                    out_kc = gr.Markdown(label="Kill Chain Scenario")
                
                with gr.TabItem("🆔 Vulnerabilità & IDs"):
                    out_ids = gr.Textbox(label="CWE / MITRE / CAPEC", lines=12, interactive=False)
                
                with gr.TabItem("📜 Conformità"):
                    out_conf = gr.Markdown(label="Violazioni Standard (ISO/NIST)")
                
                with gr.TabItem("🛡️ Mitigazione"):
                    out_mit = gr.Markdown(label="Strategie di Difesa")

    # Abilita il tasto se almeno uno dei due ha dei file
    def toggle_btn(f1, f2):
        return gr.update(interactive=bool(f1 or f2))
    
    folder_input.change(toggle_btn, [folder_input, file_input], run_btn)
    file_input.change(toggle_btn, [folder_input, file_input], run_btn)

    analysis_event = run_btn.click(
        fn=process_combined,
        inputs=[folder_input, file_input],
        outputs=[status, out_pattern, out_kc, out_ids, out_conf, out_mit]
    )
    stop_btn.click(fn=None, cancels=[analysis_event])

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860, theme=gr.themes.Soft())