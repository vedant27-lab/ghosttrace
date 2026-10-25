
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from pypdf import PdfReader
from PIL import Image
import pytesseract



@dataclass
class EvidenceDocument:

    file_id: str
    path: str
    origin: str
    captured_at: str
    file_type: str
    content: str = ""
    extraction_method: str = ""
    extraction_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _extract_pdf(path: Path) -> tuple[str, str]:
    try:
        reader = PdfReader(str(path))
        pages = []

        for page_number, page in enumerate(reader.pages, start=1):
            page_text = page.extract_text() or ""
            pages.append(f"[Page {page_number}]\n{page_text}")

        return "\n\n".join(pages), ""
    except Exception as exc:
        return "", f"PDF extraction failed: {type(exc).__name__}: {exc}"


def _extract_image_text(path: Path) -> tuple[str, str]:
    try:
        with Image.open(path) as image:
            text = pytesseract.image_to_string(image)

        return text, ""
    except Exception as exc:
        return "", f"Image OCR failed: {type(exc).__name__}: {exc}"


def _read_evidence_file(path: Path) -> tuple[str, str, str]:
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        content, error = _extract_pdf(path)
        return content, "pypdf", error

    if suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}:
        content, error = _extract_image_text(path)
        return content, "ocr", error

    if suffix == ".json":
        try:
            raw_text = path.read_text(encoding="utf-8-sig")
            parsed = json.loads(raw_text)
            return json.dumps(parsed, ensure_ascii=False, indent=2), "json", ""
        except (UnicodeError, json.JSONDecodeError) as exc:
            return "", "json", f"JSON parsing failed: {type(exc).__name__}: {exc}"

    if suffix in {".sql", ".log", ".txt", ".csv"}:
        try:
            return path.read_text(encoding="utf-8-sig"), "text", ""
        except UnicodeError:
            try:
                return path.read_text(encoding="utf-8", errors="replace"), "text", (
                    "Some characters required replacement during text decoding"
                )
            except OSError as exc:
                return "", "text", f"Text reading failed: {exc}"

    return "", "unsupported", f"Unsupported evidence file type: {suffix or '[no extension]'}"


def load_manifest(dataset_dir: str | Path) -> list[EvidenceDocument]:
    dataset_path = Path(dataset_dir).resolve()
    manifest_path = dataset_path / "evidence_files.csv"

    if not manifest_path.is_file():
        raise FileNotFoundError(f"Evidence manifest not found: {manifest_path}")

    documents: list[EvidenceDocument] = []
    seen_ids: set[str] = set()

    with manifest_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)

        required_columns = {"file_id", "file_path", "origin", "captured_at"}
        actual_columns = set(reader.fieldnames or [])
        missing_columns = required_columns - actual_columns

        if missing_columns:
            raise ValueError(
                "Evidence manifest is missing columns: "
                + ", ".join(sorted(missing_columns))
            )

        for row_number, row in enumerate(reader, start=2):
            file_id = (row.get("file_id") or "").strip()
            relative_path = (row.get("file_path") or "").strip()

            if not file_id or not relative_path:
                raise ValueError(
                    f"Manifest row {row_number} has an empty file_id or file_path"
                )

            if file_id in seen_ids:
                raise ValueError(f"Duplicate evidence file_id: {file_id}")

            seen_ids.add(file_id)
            path = (dataset_path / relative_path).resolve()

            if not path.is_relative_to(dataset_path):
                raise ValueError(
                    f"Evidence path escapes dataset directory at row {row_number}: "
                    f"{relative_path}"
                )

            documents.append(
                EvidenceDocument(
                    file_id=file_id,
                    path=str(path),
                    origin=(row.get("origin") or "").strip(),
                    captured_at=(row.get("captured_at") or "").strip(),
                    file_type=path.suffix.lower().lstrip("."),
                )
            )

    return documents


def load_all_evidence(dataset_dir: str | Path) -> list[EvidenceDocument]:
    """Load every manifest entry without silently discarding failures."""
    documents = load_manifest(dataset_dir)

    for document in documents:
        path = Path(document.path)

        if not path.is_file():
            document.extraction_error = "Evidence file does not exist"
            document.extraction_method = "missing"
            continue

        (
            document.content,
            document.extraction_method,
            document.extraction_error,
        ) = _read_evidence_file(path)

    return documents


def summarize_evidence(documents: list[EvidenceDocument]) -> dict[str, Any]:
    """Produce a compact diagnostic summary of an evidence loading run."""
    by_type: dict[str, int] = {}
    failed: list[dict[str, str]] = []
    empty: list[str] = []

    for document in documents:
        by_type[document.file_type] = by_type.get(document.file_type, 0) + 1

        if document.extraction_error:
            failed.append(
                {
                    "file_id": document.file_id,
                    "path": document.path,
                    "error": document.extraction_error,
                }
            )

        if not document.content.strip() and not document.extraction_error:
            empty.append(document.file_id)

    return {
        "manifest_entries": len(documents),
        "file_types": dict(sorted(by_type.items())),
        "extraction_errors": len(failed),
        "empty_extractions": len(empty),
        "errors": failed,
        "empty_file_ids": empty,
    }
