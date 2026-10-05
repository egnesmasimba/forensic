"""Read text from case image files with the local Tesseract binary."""

import shutil
import subprocess

from fastapi import HTTPException

LANGUAGES = {
    "eng": "English",
    "fra": "French",
    "deu": "German",
    "spa": "Spanish",
    "por": "Portuguese",
    "ita": "Italian",
    "nld": "Dutch",
    "pol": "Polish",
    "rus": "Russian",
    "ara": "Arabic",
}
IMAGE_TYPES = {"image/png", "image/jpeg"}


def recognize(path: str, language: str) -> tuple[str, float]:
    if language not in LANGUAGES:
        raise HTTPException(422, "Choose a supported OCR language")
    binary = shutil.which("tesseract")
    if binary is None:
        raise HTTPException(503, "Tesseract is not installed on this server")
    try:
        completed = subprocess.run(
            [binary, path, "stdout", "-l", language, "tsv"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Tesseract took too long")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip() or "Tesseract could not read this image"
        raise HTTPException(422, detail[:300])
    return _parse_tsv(completed.stdout.decode("utf-8", "replace"))


def _parse_tsv(raw: str) -> tuple[str, float]:
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) < 2:
        return "", 0.0
    header = lines[0].split("\t")
    try:
        text_at = header.index("text")
        conf_at = header.index("conf")
    except ValueError:
        raise HTTPException(422, "Tesseract did not return word confidence")
    words = []
    scores = []
    for line in lines[1:]:
        cells = line.split("\t")
        if len(cells) <= max(text_at, conf_at):
            continue
        word = cells[text_at].strip()
        if not word:
            continue
        try:
            score = float(cells[conf_at])
        except ValueError:
            continue
        if score < 0:
            continue
        words.append(word)
        scores.append(score)
    text = " ".join(words)[:20000]
    confidence = round(sum(scores) / len(scores), 1) if scores else 0.0
    return text, confidence
