import csv
from io import BytesIO, StringIO

from fpdf import FPDF
from openpyxl import Workbook

from app.constants import STATUS_LABELS
from app.schemas import CaseSummary

COLUMNS = [
    ("id", "ID", lambda case: case.id),
    ("title", "Title", lambda case: case.title),
    ("type", "Type", lambda case: case.case_type),
    ("status", "Status", lambda case: STATUS_LABELS.get(case.status, case.status)),
    ("risk", "Risk", lambda case: case.risk),
    ("score", "Score", lambda case: case.score),
    ("assignee", "Assignee", lambda case: case.assignee),
    ("alerts", "Alerts", lambda case: case.alert_count),
    ("summary", "Summary", lambda case: case.summary),
    ("updated", "Updated", lambda case: case.updated_at.isoformat()),
]
COLUMN_KEYS = [key for key, _label, _value in COLUMNS]


def _latin(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("\r", "").encode("latin-1", "replace").decode("latin-1")


def chosen_columns(keys: list[str] | None):
    if not keys:
        return COLUMNS
    selected = []
    for key in keys:
        match = next((column for column in COLUMNS if column[0] == key), None)
        if match is None:
            raise ValueError(key)
        selected.append(match)
    return selected


def case_rows(cases: list[CaseSummary], columns=None) -> tuple[list[str], list[list[object]]]:
    used = chosen_columns(columns)
    headers = [label for _key, label, _value in used]
    rows = [[value(case) for _key, _label, value in used] for case in cases]
    return headers, rows


def spreadsheet_safe(value):
    # Prevent case content from becoming an executable spreadsheet formula.
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def build_cases_csv(cases: list[CaseSummary], columns: list[str] | None = None) -> str:
    headers, rows = case_rows(cases, columns)
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows([[spreadsheet_safe(value) for value in row] for row in rows])
    return buffer.getvalue()


def build_cases_xlsx(cases: list[CaseSummary], columns: list[str] | None = None) -> bytes:
    headers, rows = case_rows(cases, columns)
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Cases"
    sheet.append(headers)
    for row in rows:
        sheet.append([spreadsheet_safe(value) for value in row])
    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def _write(pdf: FPDF, text: str, size: int = 11, style: str = "") -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", style, size)
    pdf.multi_cell(pdf.epw, 6, _latin(text) or "-")


def _heading(pdf: FPDF, text: str) -> None:
    pdf.ln(3)
    _write(pdf, text, size=12, style="B")


def _paragraph(pdf: FPDF, text: str) -> None:
    _write(pdf, text)


def build_case_pdf(detail) -> bytes:
    pdf = FPDF()
    pdf.set_compression(False)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    _write(pdf, detail.title, size=16, style="B")
    _write(
        pdf,
        f"{STATUS_LABELS.get(detail.status, detail.status)} - {detail.case_type} - "
        f"{detail.risk} risk - score {detail.score}",
    )
    _write(pdf, f"Assignee: {detail.assignee or 'Unassigned'}")
    _heading(pdf, "Summary")
    _paragraph(pdf, detail.summary or "No summary.")
    if detail.fields:
        _heading(pdf, "Case fields")
        for field in detail.fields:
            _paragraph(pdf, f"{field.label}: {field.value or '-'}")
    _heading(pdf, "Conclusion")
    _paragraph(pdf, detail.conclusion or "No conclusion yet.")
    _heading(pdf, "Alerts")
    if not detail.alerts:
        _paragraph(pdf, "No alerts linked.")
    for alert in detail.alerts:
        _paragraph(
            pdf,
            f"{alert.score} - {alert.title} ({alert.entity_type} {alert.entity_ref}, {alert.status})",
        )
        if alert.description:
            _paragraph(pdf, alert.description)
    _heading(pdf, "Notes")
    if not detail.notes:
        _paragraph(pdf, "No notes.")
    for note in detail.notes:
        _paragraph(pdf, f"{note.author}: {note.body}")
    _heading(pdf, "Attachments")
    if not detail.attachments:
        _paragraph(pdf, "No files attached.")
    for item in detail.attachments:
        _paragraph(pdf, f"{item.original_name} ({item.size} bytes)")
    _heading(pdf, "Activity")
    for item in detail.activities:
        _paragraph(pdf, f"{item.actor}: {item.detail}")
    return bytes(pdf.output())
