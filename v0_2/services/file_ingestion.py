from __future__ import annotations

import os
import re
from pathlib import Path
from uuid import uuid4

from v0_2.models.schemas import UploadedInput

MAX_UPLOAD_SIZE_BYTES = 2 * 1024 * 1024
CODE_EXTENSIONS = {".py", ".c", ".cpp", ".cc", ".h", ".hpp", ".java", ".js", ".ts", ".go", ".rs", ".php", ".cs"}
TEXT_EXTENSIONS = {".txt", ".md", ".log", ".json", ".yaml", ".yml", ".csv", ".xml"}
SUPPORTED_EXTENSIONS = CODE_EXTENSIONS | TEXT_EXTENSIONS


class FileIngestionError(Exception):
    pass


class FileIngestionService:
    def __init__(self, upload_dir: str):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        name = os.path.basename(filename or "upload.txt")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        return safe or "upload.txt"

    @staticmethod
    def _detect_type(extension: str) -> str:
        if extension in CODE_EXTENSIONS:
            return "code"
        if extension == ".log":
            return "log"
        if extension in TEXT_EXTENSIONS:
            return "report"
        return "other"

    @staticmethod
    def _normalize_text(raw: bytes) -> str:
        text = raw.decode("utf-8", errors="ignore")
        text = text.replace("\x00", "")
        return text.strip()

    async def ingest_upload(self, upload_file) -> UploadedInput:
        safe_name = self._sanitize_filename(upload_file.filename)
        suffix = Path(safe_name).suffix.lower()

        if suffix not in SUPPORTED_EXTENSIONS:
            raise FileIngestionError(
                f"Formato non supportato: {suffix or 'senza estensione'}. Converti il file in un formato testuale supportato."
            )

        raw = await upload_file.read()
        size = len(raw)
        if size == 0:
            raise FileIngestionError("File vuoto: carica un file con contenuto.")
        if size > MAX_UPLOAD_SIZE_BYTES:
            raise FileIngestionError("File troppo grande: limite massimo 2MB.")

        normalized = self._normalize_text(raw)
        if not normalized:
            raise FileIngestionError("Il file non contiene testo analizzabile.")

        stored_name = f"{uuid4().hex}_{safe_name}"
        stored_path = self.upload_dir / stored_name
        stored_path.write_bytes(raw)

        return UploadedInput(
            original_filename=safe_name,
            stored_path=str(stored_path),
            normalized_text=normalized,
            file_type=self._detect_type(suffix),
            size_bytes=size,
        )
