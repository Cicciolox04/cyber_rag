from __future__ import annotations

import json
import os
from typing import List
from uuid import uuid4

import requests
from langchain_chroma import Chroma
from langchain_ollama import ChatOllama, OllamaEmbeddings

from v0_2.models.schemas import AnalysisResult, Evidence, UploadedInput


class AnalysisEngineError(Exception):
    pass


class UnifiedAnalysisEngine:
    def __init__(
        self,
        db_dir: str,
        ollama_url: str = "http://10.0.2.2:11434",
        embedding_model: str = "bge-m3",
        llm_model: str = "mistral",
    ):
        self.db_dir = db_dir
        self.ollama_url = ollama_url
        self.embedding_model = embedding_model
        self.llm_model = llm_model
        self._embeddings = None
        self._db = None
        self._llm = None

    def check_ollama(self, timeout_sec: int = 3) -> None:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=timeout_sec)
            r.raise_for_status()
        except Exception as exc:
            raise AnalysisEngineError(
                f"Ollama non raggiungibile su {self.ollama_url}. Verifica servizio e rete prima di avviare l'analisi."
            ) from exc

    def _ensure_clients(self) -> None:
        if self._embeddings is None:
            self._embeddings = OllamaEmbeddings(model=self.embedding_model, base_url=self.ollama_url)
        if self._db is None:
            self._db = Chroma(persist_directory=self.db_dir, embedding_function=self._embeddings)
        if self._llm is None:
            self._llm = ChatOllama(model=self.llm_model, base_url=self.ollama_url, temperature=0.1)

    @staticmethod
    def _strip_json_markdown(text: str) -> str:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.replace("json", "", 1).strip()
        return cleaned

    @staticmethod
    def _build_context(evidence: List[Evidence]) -> str:
        parts = []
        for ev in evidence:
            score_txt = f" score={ev.score:.4f}" if ev.score is not None else ""
            parts.append(
                f"[{ev.source_type.upper()}] ID={ev.item_id} | Nome={ev.name}{score_txt}\nEstratto: {ev.excerpt}"
            )
        return "\n---\n".join(parts)

    def _retrieve_evidence(self, query_text: str, k: int = 5) -> List[Evidence]:
        assert self._db is not None
        results = self._db.similarity_search_with_score(query_text, k=k)
        evidence: List[Evidence] = []
        for doc, score in results:
            evidence.append(
                Evidence(
                    item_id=doc.metadata.get("id", "N/A"),
                    name=doc.metadata.get("name", "N/A"),
                    source_type=doc.metadata.get("type", "unknown"),
                    score=float(score) if score is not None else None,
                    excerpt=(doc.page_content or "")[:700],
                )
            )
        return evidence

    def _prompt_for_mode(self, file_type: str, input_text: str, context: str, evidence_context: str, priority: str) -> str:
        common = f"""
Sei un agente di Cyber Threat Intelligence e Security Analysis.

INPUT UTENTE:
{input_text}

CONTESTO OPERATIVO:
- mode: {file_type}
- priorita: {priority}
- note aggiuntive: {context or 'N/A'}

EVIDENZE RETRIEVAL (MITRE/CWE):
{evidence_context}

Rispondi SOLO in JSON valido con questa struttura:
{{
  "executive_summary": "...",
  "most_likely_pattern_id": "CWE-xxx o Txxxx o N/A",
  "predicted_next_step": "...",
  "immediate_actions": ["azione 1", "azione 2"],
  "raw_conclusion": "ragionamento finale sintetico"
}}
"""

        if file_type == "code":
            return common + "\nFocus: secure coding, funzione/riga insicura, mapping CWE/MITRE e mitigazione concreta."
        if file_type in {"report", "log"}:
            return common + "\nFocus: evento osservato, tecnica probabile, progressione attacco e containment iniziale."
        return common + "\nFocus: estrarre segnali utili e proporre una valutazione prudente."

    def analyze(self, uploaded: UploadedInput, mode: str = "immediate", context: str = "", priority: str = "medium") -> AnalysisResult:
        self.check_ollama()
        self._ensure_clients()

        evidence = self._retrieve_evidence(uploaded.normalized_text, k=5)
        evidence_context = self._build_context(evidence)
        prompt = self._prompt_for_mode(uploaded.file_type, uploaded.normalized_text[:6000], context, evidence_context, priority)

        try:
            response = self._llm.invoke(prompt).content
            payload = json.loads(self._strip_json_markdown(response))

            return AnalysisResult(
                analysis_id=uuid4().hex,
                original_filename=uploaded.original_filename,
                source_path=uploaded.stored_path,
                file_type=uploaded.file_type,
                mode=mode,
                context=context,
                priority=priority,
                executive_summary=payload.get("executive_summary", ""),
                most_likely_pattern_id=payload.get("most_likely_pattern_id", "N/A"),
                predicted_next_step=payload.get("predicted_next_step", ""),
                immediate_actions=[str(x) for x in payload.get("immediate_actions", [])][:5],
                raw_conclusion=payload.get("raw_conclusion", response),
                evidence=evidence,
            )
        except Exception:
            return AnalysisResult(
                analysis_id=uuid4().hex,
                original_filename=uploaded.original_filename,
                source_path=uploaded.stored_path,
                file_type=uploaded.file_type,
                mode=mode,
                context=context,
                priority=priority,
                status="failed",
                error="Errore durante l'analisi del modello.",
                executive_summary="Analisi non completata.",
                raw_conclusion="Output del modello non valido o non disponibile.",
                evidence=evidence,
            )
