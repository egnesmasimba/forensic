import re
import uuid

from sqlalchemy.orm import Session, selectinload

from app.models import FieldAudit, ScreenDefinition, ScreenField, ScreenHit, ScreenMarker

FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
FIELD_ACTIONS = ("read", "update", "add", "delete")


def screen_query(db: Session):
    return db.query(ScreenDefinition).options(
        selectinload(ScreenDefinition.markers),
        selectinload(ScreenDefinition.fields),
    )


def _marker_found(lines: list[str], marker: ScreenMarker) -> bool:
    if marker.line == 0:
        return any(marker.text in line for line in lines)
    index = marker.line - 1
    return 0 <= index < len(lines) and marker.text in lines[index]


def matching_screens(screens: list[ScreenDefinition], text: str) -> list[ScreenDefinition]:
    lines = text.splitlines()
    found = []
    for screen in screens:
        if screen.markers and all(_marker_found(lines, marker) for marker in screen.markers):
            found.append(screen)
    return found


def extract_fields(screen: ScreenDefinition, text: str) -> list[dict]:
    lines = text.splitlines()
    captured = []
    for field in screen.fields:
        raw = lines[field.line - 1] if 0 <= field.line - 1 < len(lines) else ""
        start = max(field.start_column - 1, 0)
        captured.append({
            "name": field.name,
            "label": field.label,
            "action": field.action,
            "value": raw[start:start + field.length].strip()[:500],
        })
    return captured


def identify_text(db: Session, text: str) -> tuple[ScreenDefinition | None, list[str]]:
    matched = matching_screens(screen_query(db).order_by(ScreenDefinition.id).all(), text)
    if len(matched) != 1:
        return None, [screen.name for screen in matched]
    return matched[0], []


def record_hit(
    db: Session,
    screen: ScreenDefinition,
    text: str,
    *,
    source: str,
    username: str,
    attachment_id: int | None = None,
    process_id: int | None = None,
    step_position: int = 0,
    occurrence_key: str | None = None,
) -> ScreenHit:
    hit = ScreenHit(
        occurrence_key=occurrence_key or uuid.uuid4().hex,
        process_id=process_id,
        screen_id=screen.id,
        step_position=step_position,
        source=source,
        attachment_id=attachment_id,
        created_by=username,
    )
    db.add(hit)
    db.flush()
    for item in extract_fields(screen, text):
        db.add(FieldAudit(
            hit_id=hit.id,
            name=item["name"],
            label=item["label"],
            action=item["action"],
            value=item["value"],
        ))
    from app.analytics import evaluate_rules, note_screen
    note_screen(db, hit, screen.name)
    evaluate_rules(db, {("user", hit.created_by or "unknown")})
    return hit


def note_image_reading(db: Session, text: str, username: str, attachment_id: int) -> str:
    screen, names = identify_text(db, text)
    if screen is None:
        return ""
    record_hit(db, screen, text, source="image", username=username, attachment_id=attachment_id)
    return screen.name


def valid_field_name(name: str) -> bool:
    return bool(FIELD_NAME.fullmatch(name))
