import hashlib
import hmac
import json
import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from app.behavior import _stamp, indicator_series
from app.models import (
    Alert, BusinessEntity, Fact, IndicatorDefinition, LibraryFinding, LibraryRule, Prediction,
    SyntheticProfile, SyntheticSalt,
)

CATALOG_VERSION = 2
LIBRARY = (
    ("nist-ac-2", "nist", "AC-2 account access count", "account_access", "count", 10, 70),
    ("nist-si-4", "nist", "SI-4 transfer amount", "transfer", "sum", 1000, 80),
    ("nist-au-6", "nist", "AU-6 customer name queries", "customer_name_query", "count", 5, 60),
    ("mitre-t1078", "mitre", "T1078 distinct accounts", "account_access", "distinct", 3, 70),
    ("mitre-t1537", "mitre", "T1537 transfer count", "transfer", "count", 8, 75),
    ("cert-beneficiary", "cert", "CERT beneficiary changes", "beneficiary_change", "count", 3, 70),
    ("cert-attribute", "cert", "CERT attribute changes", "attribute_change", "count", 4, 65),
    ("fsisac-wires", "fsisac", "FS-ISAC wire count", "transfer", "count", 8, 80),
)


def seed_library(db: Session) -> int:
    return update_library(db)


def update_library(db: Session) -> int:
    added = 0
    for key, framework, name, fact_name, measure, threshold, score in LIBRARY:
        row = db.query(LibraryRule).filter_by(key=key).one_or_none()
        if row is None:
            db.add(LibraryRule(
                key=key, framework=framework, name=name, fact_name=fact_name, measure=measure,
                threshold=threshold, score=score, enabled=True, customized=False, catalog_version=CATALOG_VERSION,
            ))
            added += 1
        elif not row.customized:
            row.name = name
            row.fact_name = fact_name
            row.measure = measure
            row.threshold = threshold
            row.score = score
            row.catalog_version = CATALOG_VERSION
    from app.indicator_catalog import threat_catalog
    existing = {row.key: row for row in db.query(LibraryRule)}
    for item in threat_catalog():
        values = {key: item[key] for key in ('key', 'framework', 'name', 'fact_name', 'measure', 'window_days', 'threshold', 'score')}
        row = existing.get(item['key'])
        if row is None:
            db.add(LibraryRule(**values, enabled=True, customized=False, catalog_version=CATALOG_VERSION)); added += 1
        elif not row.customized:
            for key, value in values.items(): setattr(row, key, value)
            row.catalog_version = CATALOG_VERSION
    db.commit()
    return added


def _week(moment) -> str:
    year, week, _day = moment.isocalendar()
    return f"{year}-W{week:02d}"


def _facts(db: Session, entity_ref: str, name: str, start, end) -> list[Fact]:
    rows = db.query(Fact).filter_by(entity_type="user", entity_ref=entity_ref, name=name).all()
    selected = []
    for row in rows:
        moment = _stamp(row.occurred_at)
        if moment is not None and start <= moment <= end:
            selected.append(row)
    return selected


def _daily(db: Session, entity_ref: str, name: str, as_of, days: int, measure: str = "sum") -> list[float]:
    start = as_of - timedelta(days=days - 1)
    buckets = {}
    cursor = start
    while cursor <= as_of:
        buckets[cursor.strftime("%Y-%m-%d")] = []
        cursor += timedelta(days=1)
    for row in _facts(db, entity_ref, name, start, as_of):
        moment = _stamp(row.occurred_at)
        key = moment.strftime("%Y-%m-%d")
        if key in buckets:
            buckets[key].append(row)
    values = []
    for rows in buckets.values():
        if measure == "count":
            values.append(float(len(rows)))
        else:
            values.append(float(sum(row.numeric_value for row in rows)))
    return values


def _open_prediction(db: Session, entity_ref: str, kind: str, as_of, score: int, detail: str, title: str) -> int | None:
    period = _week(as_of)
    if db.query(Prediction).filter_by(entity_ref=entity_ref, kind=kind, period_key=period).one_or_none() is not None:
        return None
    alert = Alert(
        title=title, score=score, status="open", entity_type="user", entity_ref=entity_ref,
        channel="analytic", description=detail[:500],
    )
    db.add(alert)
    db.flush()
    db.add(Prediction(
        entity_ref=entity_ref, kind=kind, score=score, detail=detail[:200], period_key=period, alert_id=alert.id,
    ))
    return alert.id


def threat_prediction(db: Session, entity_ref: str, as_of) -> dict:
    values = _daily(db, entity_ref, "transfer", as_of, 90, "count")
    recent, earlier = values[-14:], values[:-14]
    recent_mean = sum(recent) / len(recent) if recent else 0.0
    earlier_mean = sum(earlier) / len(earlier) if earlier else 0.0
    rising = earlier_mean > 0 and recent_mean >= earlier_mean * 2 and recent_mean >= 1
    score = min(100, int(recent_mean / earlier_mean * 25)) if rising else 0
    return {"recent_mean": recent_mean, "earlier_mean": earlier_mean, "rising": rising, "score": score}


def workload(db: Session, entity_ref: str, as_of) -> dict:
    values = _daily(db, entity_ref, "work_minutes", as_of, 90, "sum")
    recent, earlier = values[-14:], values[:-14]
    overwork_days = sum(1 for value in recent if value >= 600)
    recent_mean = sum(recent) / len(recent) if recent else 0.0
    earlier_mean = sum(earlier) / len(earlier) if earlier else 0.0
    disengaged = earlier_mean >= 120 and recent_mean < earlier_mean * 0.5
    start = as_of - timedelta(days=29)
    turnover = len(_facts(db, entity_ref, "turnover_signal", start, as_of))
    score = min(100, overwork_days * 20 + (30 if disengaged else 0) + turnover * 25)
    return {
        "overwork_days": overwork_days, "disengaged": disengaged, "turnover_signals": turnover,
        "recent_mean": recent_mean, "earlier_mean": earlier_mean, "score": score,
    }


def time_use(db: Session, entity_ref: str, as_of) -> dict:
    start = as_of - timedelta(days=89)
    totals = {"work": 0.0, "meeting": 0.0, "idle": 0.0}
    for row in _facts(db, entity_ref, "activity_minutes", start, as_of):
        kind = (row.text_value or "").casefold()
        if kind in totals:
            totals[kind] += row.numeric_value
    for kind, name in (("work", "work_minutes"), ("meeting", "meeting_minutes"), ("idle", "idle_minutes")):
        totals[kind] += sum(row.numeric_value for row in _facts(db, entity_ref, name, start, as_of))
    total = sum(totals.values())
    return {
        "work": totals["work"],
        "meeting_minutes": totals["meeting"],
        "idle_minutes": totals["idle"],
        "productivity": totals["work"] / total if total else 0.0,
        "meeting": totals["meeting"] > 0,
        "idle": totals["idle"] > 0,
    }


def sentiment(db: Session, entity_ref: str, as_of) -> dict:
    start = as_of - timedelta(days=89)
    rows = _facts(db, entity_ref, "sentiment_signal", start, as_of)
    average = sum(row.numeric_value for row in rows) / len(rows) if rows else 0.0
    if average >= 0.3:
        label = "steady"
    elif average <= -0.5:
        label = "strained"
    else:
        label = "mixed"
    distressed = any((row.text_value or "").casefold() == "distressed" for row in rows) or (len(rows) >= 2 and average <= -0.8)
    return {
        "count": len(rows), "average": average, "label": label,
        "disgruntled": len(rows) >= 2 and average <= -0.5,
        "distressed": distressed,
    }


def review_user(db: Session, entity_ref: str, as_of) -> dict:
    return {
        "entity_ref": entity_ref,
        "threat": threat_prediction(db, entity_ref, as_of),
        "workload": workload(db, entity_ref, as_of),
        "time_use": time_use(db, entity_ref, as_of),
        "sentiment": sentiment(db, entity_ref, as_of),
    }


def record_profile(db: Session, entity_ref: str, as_of) -> list[int]:
    picture = review_user(db, entity_ref, as_of)
    created = []
    threat = picture["threat"]
    if threat["rising"]:
        alert_id = _open_prediction(
            db, entity_ref, "threat", as_of, threat["score"],
            f"Recent transfers average {threat['recent_mean']:.2f} against an earlier average of {threat['earlier_mean']:.2f}. Review this user.",
            "Threat prediction",
        )
        if alert_id:
            created.append(alert_id)
    load = picture["workload"]
    if load["score"] >= 60:
        alert_id = _open_prediction(
            db, entity_ref, "burnout", as_of, load["score"],
            f"Workload score {load['score']}: {load['overwork_days']} long days, disengaged {load['disengaged']}.",
            "Burnout risk",
        )
        if alert_id:
            created.append(alert_id)
    if load["turnover_signals"]:
        alert_id = _open_prediction(
            db, entity_ref, "turnover", as_of, min(100, 50 + load["turnover_signals"] * 10),
            f"{load['turnover_signals']} turnover signals are on record.",
            "Turnover signal",
        )
        if alert_id:
            created.append(alert_id)
    mood = picture["sentiment"]
    if mood["disgruntled"] or mood["distressed"]:
        alert_id = _open_prediction(
            db, entity_ref, "sentiment", as_of, 60,
            f"Sentiment signals average {mood['average']:.2f} ({mood['label']}).",
            "Sentiment signal",
        )
        if alert_id:
            created.append(alert_id)
    created.extend(evaluate_library(db, entity_ref, as_of))
    return created


def _library_value(rows: list[Fact], measure: str) -> float:
    if measure == "distinct":
        return float(len({row.text_value for row in rows if row.text_value}))
    if measure == "sum":
        return float(sum(row.numeric_value for row in rows))
    return float(len(rows))


def evaluate_library(db: Session, entity_ref: str, as_of) -> list[int]:
    created = []
    cached = {}
    for rule in db.query(LibraryRule).filter_by(enabled=True).all():
        start = as_of - timedelta(days=rule.window_days)
        period = as_of.strftime('%Y-%m-%d') if rule.window_days == 1 else as_of.strftime('%Y-%m') if rule.window_days == 30 else _week(as_of)
        cache_key = (rule.fact_name, rule.window_days)
        if cache_key not in cached: cached[cache_key] = _facts(db, entity_ref, rule.fact_name, start, as_of)
        value = _library_value(cached[cache_key], rule.measure)
        if value < rule.threshold:
            continue
        if db.query(LibraryFinding).filter_by(rule_key=rule.key, entity_ref=entity_ref, period_key=period).one_or_none():
            continue
        alert = Alert(
            title=f"Library: {rule.name}", score=rule.score, status="open", entity_type="user",
            entity_ref=entity_ref, channel="analytic",
            description=f"{rule.framework} {rule.name}: {value:g} compared with {rule.threshold:g}.",
        )
        db.add(alert)
        db.flush()
        db.add(LibraryFinding(rule_key=rule.key, entity_ref=entity_ref, period_key=period, value=value, alert_id=alert.id))
        created.append(alert.id)
    return created


def _salt(db: Session) -> str:
    row = db.get(SyntheticSalt, 1)
    if row is None:
        row = SyntheticSalt(id=1, secret=secrets.token_hex(16))
        db.add(row)
        db.flush()
    return row.secret


def build_twin(db: Session, entity_ref: str, as_of) -> dict:
    token = hmac.new(_salt(db).encode(), entity_ref.encode(), hashlib.sha256).hexdigest()[:24]
    indicators = []
    for definition in db.query(IndicatorDefinition).order_by(IndicatorDefinition.id).all():
        series = indicator_series(db, definition, entity_ref, as_of)
        indicators.append({"key": series["key"], "label": series["label"], "average": series["average"]})
    payload = {"indicators": indicators}
    row = db.query(SyntheticProfile).filter_by(token=token).one_or_none()
    if row is None:
        row = SyntheticProfile(token=token, entity_ref=entity_ref, payload=json.dumps(payload))
        db.add(row)
    else:
        row.payload = json.dumps(payload)
    db.flush()
    return {"token": token, "indicators": indicators}


def peers(db: Session, entity_ref: str, as_of) -> dict:
    definition = db.query(IndicatorDefinition).filter_by(key="transfer_count").one_or_none()
    totals = {}
    if definition is not None:
        refs = [row[0] for row in db.query(Fact.entity_ref).filter_by(entity_type="user", name="transfer").distinct().all()]
        for ref in refs:
            totals[ref] = indicator_series(db, definition, ref, as_of)["total"]
    user_value = totals.get(entity_ref, 0.0)
    others = [value for ref, value in totals.items() if ref != entity_ref]
    peer_mean = sum(others) / len(others) if others else 0.0
    entity = db.query(BusinessEntity).filter_by(entity_type="user", entity_ref=entity_ref).one_or_none()
    static = json.loads(entity.static_info or "{}") if entity else {}

    def same(attribute: str) -> float:
        wanted = static.get(attribute, "")
        if not wanted:
            return 0.0
        matched = []
        for ref in totals:
            other = db.query(BusinessEntity).filter_by(entity_type="user", entity_ref=ref).one_or_none()
            info = json.loads(other.static_info or "{}") if other else {}
            if info.get(attribute) == wanted:
                matched.append(totals[ref])
        return sum(matched) / len(matched) if matched else 0.0

    return {
        "entity_ref": entity_ref,
        "transfer_count": user_value,
        "peer_mean": peer_mean,
        "above_peers": peer_mean > 0 and user_value >= peer_mean * 2,
        "department_mean": same("department"),
        "role_mean": same("role"),
    }


def group_profile(db: Session, entity_type: str, group: str, as_of) -> dict:
    members = []
    definition = db.query(IndicatorDefinition).filter_by(key="transfer_count").one_or_none()
    for entity in db.query(BusinessEntity).filter_by(entity_type=entity_type).all():
        if json.loads(entity.static_info or "{}").get("group") != group:
            continue
        total = indicator_series(db, definition, entity.entity_ref, as_of)["total"] if definition and entity_type == "user" else 0.0
        members.append({"entity_ref": entity.entity_ref, "transfer_count": total})
    average = sum(row["transfer_count"] for row in members) / len(members) if members else 0.0
    return {"entity_type": entity_type, "group": group, "average": average, "members": members}
