import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import Alert, AnalyticRule, BusinessEntity, Fact, RiskEvent, RiskSetting, RuleFinding

ENTITY_TYPES = ("user", "account", "customer", "other")
AGGREGATIONS = ("sum", "count", "min", "max")
COMPARATORS = ("gte", "lte")


def _entity(db: Session, entity_type: str, entity_ref: str) -> BusinessEntity:
    row = db.query(BusinessEntity).filter_by(entity_type=entity_type, entity_ref=entity_ref).one_or_none()
    if row is None:
        row = BusinessEntity(entity_type=entity_type, entity_ref=entity_ref, static_info="{}", dynamic_info="{}")
        db.add(row)
        db.flush()
    return row


def remember_fact(
    db: Session,
    *,
    source_key: str,
    source: str,
    occurred_at: str,
    entity_type: str,
    entity_ref: str,
    name: str,
    numeric_value: float = 0,
    text_value: str = "",
) -> None:
    if db.query(Fact).filter_by(source_key=source_key).one_or_none() is not None:
        return
    db.add(Fact(
        source_key=source_key[:200],
        source=source,
        occurred_at=occurred_at[:40],
        entity_type=entity_type,
        entity_ref=entity_ref[:120],
        name=name[:40],
        numeric_value=float(numeric_value),
        text_value=text_value[:200],
    ))
    entity = _entity(db, entity_type, entity_ref[:120])
    dynamic = json.loads(entity.dynamic_info or "{}")
    dynamic["fact_count"] = int(dynamic.get("fact_count", 0)) + 1
    dynamic["last_occurred_at"] = occurred_at[:40]
    entity.dynamic_info = json.dumps(dynamic)


def note_activity(db: Session, events, source: str) -> None:
    for event in events:
        stamp = event.occurred_at.isoformat()
        key = f"activity:{source}:{event.event_id}"
        remember_fact(db, source_key=key + ":bytes", source="activity", occurred_at=stamp,
                      entity_type="user", entity_ref=event.user, name="bytes", numeric_value=event.bytes)
        remember_fact(db, source_key=key + ":records", source="activity", occurred_at=stamp,
                      entity_type="user", entity_ref=event.user, name="records", numeric_value=event.records)
        remember_fact(db, source_key=key + ":action", source="activity", occurred_at=stamp,
                      entity_type="user", entity_ref=event.user, name="action", numeric_value=1, text_value=event.action)
        remember_fact(db, source_key=key + ":terminal", source="activity", occurred_at=stamp,
                      entity_type="user", entity_ref=event.user, name="terminal", numeric_value=1, text_value=event.destination)


def note_visit(db: Session, visit) -> None:
    remember_fact(
        db,
        source_key=f"website:{visit.source}:{visit.visit_id}",
        source="website",
        occurred_at=visit.occurred_at,
        entity_type="user",
        entity_ref=visit.user,
        name="visit_seconds",
        numeric_value=visit.seconds,
        text_value=visit.host,
    )


def note_screen(db: Session, hit, screen_name: str) -> None:
    remember_fact(
        db,
        source_key=f"screen:{hit.id}",
        source="screen",
        occurred_at=hit.created_at.isoformat(),
        entity_type="user",
        entity_ref=hit.created_by or "unknown",
        name="screen",
        numeric_value=1,
        text_value=screen_name,
    )


def _aggregate(kind: str, values: list[float]) -> float | None:
    if not values:
        return None
    if kind == "count":
        return float(len(values))
    if kind == "sum":
        return float(sum(values))
    if kind == "min":
        return float(min(values))
    if kind == "max":
        return float(max(values))
    return None


def _matches(comparator: str, value: float, threshold: float) -> bool:
    if comparator == "lte":
        return value <= threshold
    return value >= threshold


def rule_options(rule: AnalyticRule) -> dict:
    try:
        loaded = json.loads(rule.options or "{}")
    except json.JSONDecodeError:
        loaded = {}
    return loaded if isinstance(loaded, dict) else {}


def _hour(stamp: str) -> int | None:
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).hour
    except ValueError:
        return None


def _attribute_ok(db: Session, rule: AnalyticRule, entity_type: str, entity_ref: str) -> bool:
    if not rule.attribute_key:
        return rule_options(rule).get("kind") != "where"
    entity = db.query(BusinessEntity).filter_by(entity_type=entity_type, entity_ref=entity_ref).one_or_none()
    static = json.loads(entity.static_info or "{}") if entity is not None else {}
    return str(static.get(rule.attribute_key, "")) == rule.attribute_value


def _selected_facts(db: Session, rule: AnalyticRule, only: set[tuple[str, str]] | None) -> list[Fact]:
    rows = db.query(Fact).filter_by(entity_type=rule.entity_type, name=rule.fact_name).all()
    kept = []
    for fact in rows:
        if only is not None and (fact.entity_type, fact.entity_ref) not in only:
            continue
        if not _attribute_ok(db, rule, fact.entity_type, fact.entity_ref):
            continue
        kept.append(fact)
    return kept


def _matches_for(db: Session, rule: AnalyticRule, only: set[tuple[str, str]] | None) -> list[tuple[str, str, float]]:
    kind = rule_options(rule).get("kind", "aggregation")
    options = rule_options(rule)
    if kind == "data_correlation":
        rows = db.query(Fact).filter_by(entity_type=rule.entity_type, name=rule.fact_name).all()
        grouped: dict[str, set[str]] = {}
        for fact in rows:
            if fact.text_value:
                grouped.setdefault(fact.text_value, set()).add(fact.entity_ref)
        matches = []
        for text, refs in grouped.items():
            if len(refs) < max(rule.threshold, 2):
                continue
            if only is not None and not any((rule.entity_type, ref) in only for ref in refs):
                continue
            matches.append((rule.entity_type, text[:120], float(len(refs))))
        return matches
    facts = _selected_facts(db, rule, None if kind == "data_correlation" else only)
    if kind == "what":
        listed = {item.strip() for item in options.get("list_values", "").split(",") if item.strip()}
        mode = options.get("list_mode", "deny")
        grouped: dict[str, int] = {}
        for fact in facts:
            listed_hit = fact.text_value in listed
            if (mode == "deny" and listed_hit) or (mode == "allow" and fact.text_value and not listed_hit):
                grouped[fact.entity_ref] = grouped.get(fact.entity_ref, 0) + 1
        return [(rule.entity_type, ref, float(count)) for ref, count in grouped.items() if count >= max(rule.threshold, 1)]
    if kind == "how":
        pattern = str(options.get("pattern", "")).casefold()
        grouped = {}
        for fact in facts:
            if pattern and pattern in fact.text_value.casefold():
                grouped[fact.entity_ref] = grouped.get(fact.entity_ref, 0) + 1
        return [(rule.entity_type, ref, float(count)) for ref, count in grouped.items() if count >= max(rule.threshold, 1)]
    if kind == "when":
        start = int(options.get("start_hour", 8))
        end = int(options.get("end_hour", 18))
        grouped = {}
        for fact in facts:
            hour = _hour(fact.occurred_at)
            if hour is not None and (hour < start or hour >= end):
                grouped[fact.entity_ref] = grouped.get(fact.entity_ref, 0) + 1
        return [(rule.entity_type, ref, float(count)) for ref, count in grouped.items() if count >= max(rule.threshold, 1)]
    if kind == "time_correlation":
        grouped: dict[str, set[str]] = {}
        for fact in facts:
            if fact.text_value:
                grouped.setdefault(fact.entity_ref, set()).add(fact.text_value)
        needed = max(rule.threshold, 2)
        return [(rule.entity_type, ref, float(len(values))) for ref, values in grouped.items() if len(values) >= needed]
    if kind == "process":
        steps = [item.strip() for item in options.get("steps", "").split(",") if item.strip()]
        grouped: dict[str, list[Fact]] = {}
        for fact in facts:
            grouped.setdefault(fact.entity_ref, []).append(fact)
        matches = []
        for ref, rows in grouped.items():
            pending = list(steps)
            for fact in sorted(rows, key=lambda item: item.occurred_at):
                if pending and (fact.text_value == pending[0] or fact.name == pending[0]):
                    pending.pop(0)
            if steps and not pending:
                matches.append((rule.entity_type, ref, float(len(steps))))
        return matches
    grouped: dict[str, list[float]] = {}
    for fact in facts:
        grouped.setdefault(fact.entity_ref, []).append(fact.numeric_value)
    matches = []
    for entity_ref, values in grouped.items():
        value = _aggregate(rule.aggregation, values)
        if value is not None and _matches(rule.comparator, value, rule.threshold):
            matches.append((rule.entity_type, entity_ref, value))
    return matches


def score_threshold(db: Session) -> int:
    row = db.get(RiskSetting, 1)
    if row is None:
        row = RiskSetting(id=1, threshold=100)
        db.add(row)
        db.flush()
    return row.threshold


def current_score(db: Session, entity_type: str, entity_ref: str) -> int:
    latest = (
        db.query(RiskEvent)
        .filter_by(entity_type=entity_type, entity_ref=entity_ref)
        .order_by(RiskEvent.id.desc())
        .first()
    )
    return latest.score if latest is not None else 0


def add_score(db: Session, entity_type: str, entity_ref: str, delta: int, reason: str) -> int:
    previous = current_score(db, entity_type, entity_ref)
    updated = previous + delta
    db.add(RiskEvent(entity_type=entity_type, entity_ref=entity_ref, score=updated, delta=delta, reason=reason[:200]))
    db.flush()
    limit = score_threshold(db)
    if previous < limit <= updated:
        db.add(Alert(
            title="Risk score",
            score=updated,
            status="open",
            entity_type=entity_type,
            entity_ref=entity_ref,
            channel="analytic",
            description=f"Risk score reached {updated}, at or above {limit}.",
        ))
    return updated


def evaluate_rules(db: Session, only: set[tuple[str, str]] | None = None, *, persist: bool = True) -> list:
    db.flush()
    rules = db.query(AnalyticRule).filter_by(enabled=True).all()
    alert_ids = []
    preview = []
    for rule in rules:
        for entity_type, entity_ref, value in _matches_for(db, rule, only):
            detail = f"{rule_options(rule).get('kind', 'aggregation')} {value:g}"
            preview.append({
                "rule": rule.name, "version": rule.version, "entity_type": entity_type,
                "entity_ref": entity_ref, "value": value, "detail": detail,
            })
            if not persist or rule.id is None:
                continue
            existing = db.query(RuleFinding).filter_by(rule_id=rule.id, entity_type=entity_type, entity_ref=entity_ref).one_or_none()
            if existing is not None:
                continue
            alert = Alert(
                title=f"Analytic rule: {rule.name} v{rule.version}",
                score=rule.score,
                status="open",
                entity_type=entity_type,
                entity_ref=entity_ref,
                channel="analytic",
                description=f"Rule: {rule.name} version {rule.version}. {detail}.",
            )
            db.add(alert)
            db.flush()
            db.add(RuleFinding(rule_id=rule.id, entity_type=entity_type, entity_ref=entity_ref, value=value, alert_id=alert.id))
            add_score(db, entity_type, entity_ref, rule.score, f"{rule.name} v{rule.version}")
            alert_ids.append(alert.id)
    return alert_ids if persist else preview


def test_rule(db: Session, rule: AnalyticRule) -> list[dict]:
    db.flush()
    return [
        {"entity_type": entity_type, "entity_ref": entity_ref, "value": value}
        for entity_type, entity_ref, value in _matches_for(db, rule, None)
    ]
