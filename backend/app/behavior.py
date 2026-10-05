import math
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.analytics import remember_fact
from app.mail_models import MailEvidence
from app.models import Alert, BaselineSetting, BehaviorDeviation, ChannelEvent, Fact, IndicatorDefinition

CHANNELS = ("phone", "email", "chat", "system")
MEASURES = ("distinct", "count", "sum", "revert")
PERIODS = ("day", "week", "month")
BUILT_IN = (
    ("accounts_accessed", "Accounts accessed per day (3-month average)", "account_access", "distinct", "day"),
    ("dormant_accounts_accessed", "Dormant accounts accessed per week", "dormant_account_access", "distinct", "week"),
    ("address_changes", "Address changes per week", "address_change", "count", "week"),
    ("beneficiary_changes", "Beneficiary changes per week", "beneficiary_change", "count", "week"),
    ("mailing_frequency_changes", "Mailing frequency changes per week", "mailing_frequency_change", "count", "week"),
    ("dormant_attribute_changes", "Dormant account attribute changes per week", "dormant_attribute_change", "count", "week"),
    ("customer_name_queries", "Customer name queries per week", "customer_name_query", "count", "week"),
    ("transfer_amount", "Money transfers per day (amount)", "transfer", "sum", "day"),
    ("transfer_count", "Money transfers per day (count)", "transfer", "count", "day"),
    ("attribute_reverts", "Attribute change and revert within 48 hours", "attribute_change", "revert", "month"),
)


def seed_indicators(db: Session) -> None:
    for key, label, fact_name, measure, period in BUILT_IN:
        if db.query(IndicatorDefinition).filter_by(key=key).one_or_none() is None:
            db.add(IndicatorDefinition(
                key=key, label=label, fact_name=fact_name, measure=measure, period=period,
                window_days=90, built_in=True,
            ))
    from app.indicator_catalog import behavior_catalog
    existing = {row[0] for row in db.query(IndicatorDefinition.key)}
    for item in behavior_catalog():
        if item['key'] not in existing:
            db.add(IndicatorDefinition(**{key: item[key] for key in ('key', 'label', 'fact_name', 'measure', 'period', 'window_days')}, built_in=True))
    if db.get(BaselineSetting, 1) is None:
        db.add(BaselineSetting(id=1, sigma=3.0, minimum_periods=4))
    db.commit()


def _stamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _period_key(moment: datetime, period: str) -> str:
    if period == "week":
        year, week, _day = moment.isocalendar()
        return f"{year}-W{week:02d}"
    if period == "month":
        return moment.strftime("%Y-%m")
    return moment.strftime("%Y-%m-%d")


def _period_keys(start: datetime, end: datetime, period: str) -> list[str]:
    keys = []
    seen = set()
    cursor = start
    while cursor <= end:
        key = _period_key(cursor, period)
        if key not in seen:
            seen.add(key)
            keys.append(key)
        cursor += timedelta(days=1)
    return keys


def _revert_moments(facts: list[tuple[datetime, Fact]]) -> list[datetime]:
    grouped: dict[str, list[tuple[datetime, str, str]]] = {}
    for moment, fact in facts:
        parts = (fact.text_value or "").split("|")
        if len(parts) != 3:
            continue
        grouped.setdefault(parts[0], []).append((moment, parts[1], parts[2]))
    moments = []
    for changes in grouped.values():
        changes.sort(key=lambda item: item[0])
        for index, (moment, before, after) in enumerate(changes):
            for later, later_before, later_after in changes[index + 1:]:
                if later - moment > timedelta(hours=48):
                    break
                if later_before == after and later_after == before:
                    moments.append(later)
                    break
    return moments


def _measure(definition: IndicatorDefinition, rows: list[Fact]) -> float:
    if definition.measure == "distinct":
        return float(len({row.text_value for row in rows if row.text_value}))
    if definition.measure == "sum":
        return float(sum(row.numeric_value for row in rows))
    return float(len(rows))


def indicator_series(db: Session, definition: IndicatorDefinition, entity_ref: str, as_of: datetime) -> dict:
    start = as_of - timedelta(days=definition.window_days - 1)
    facts = db.query(Fact).filter_by(entity_type="user", entity_ref=entity_ref, name=definition.fact_name).all()
    selected = []
    for fact in facts:
        moment = _stamp(fact.occurred_at)
        if moment is not None and start <= moment <= as_of:
            selected.append((moment, fact))
    keys = _period_keys(start, as_of, definition.period)
    buckets = {key: [] for key in keys}
    for moment, fact in selected:
        key = _period_key(moment, definition.period)
        if key in buckets:
            buckets[key].append(fact)
    if definition.measure == "revert":
        counted = _revert_moments(selected)
        values = []
        for key in keys:
            values.append(float(sum(1 for moment in counted if _period_key(moment, definition.period) == key)))
    else:
        values = [_measure(definition, buckets[key]) for key in keys]
    total = float(sum(values))
    return {
        "key": definition.key,
        "label": definition.label,
        "fact_name": definition.fact_name,
        "measure": definition.measure,
        "period": definition.period,
        "window_days": definition.window_days,
        "built_in": definition.built_in,
        "observations": len(selected),
        "coverage": "observed" if selected else "no observations",
        "total": total,
        "average": total / len(values) if values else 0.0,
        "periods": len(values),
        "series": values,
        "latest_period": keys[-1] if keys else "",
    }


def baseline_settings(db: Session) -> BaselineSetting:
    row = db.get(BaselineSetting, 1)
    if row is None:
        row = BaselineSetting(id=1, sigma=3.0, minimum_periods=4)
        db.add(row)
        db.flush()
    return row


def _baseline_row(series: dict, sigma: float, minimum_periods: int) -> dict:
    values = series["series"]
    history = values[:-1] if values else []
    latest = values[-1] if values else 0.0
    active = sum(1 for value in history if value > 0)
    mean = sum(history) / len(history) if history else 0.0
    variance = sum((value - mean) ** 2 for value in history) / len(history) if history else 0.0
    stdev = math.sqrt(variance)
    band = mean + sigma * stdev
    ready = active >= minimum_periods
    deviated = ready and latest > mean and (stdev == 0 or latest >= band)
    deviation = 0.0 if stdev == 0 else (latest - mean) / stdev
    return {
        "key": series["key"],
        "label": series["label"],
        "mean": mean,
        "stdev": stdev,
        "latest": latest,
        "latest_period": series["latest_period"],
        "active_periods": active,
        "ready": ready,
        "deviated": deviated,
        "deviation": deviation,
    }


def refresh_user(db: Session, entity_ref: str, as_of: datetime | None = None) -> list[int]:
    moment = as_of or datetime.now(timezone.utc)
    settings = baseline_settings(db)
    created = []
    for definition in db.query(IndicatorDefinition).order_by(IndicatorDefinition.id).all():
        series = indicator_series(db, definition, entity_ref, moment)
        profile = _baseline_row(series, settings.sigma, settings.minimum_periods)
        if not profile["deviated"] or not profile["latest_period"]:
            continue
        existing = db.query(BehaviorDeviation).filter_by(
            entity_ref=entity_ref, indicator_key=definition.key, period_key=profile["latest_period"],
        ).one_or_none()
        if existing is not None:
            continue
        alert = Alert(
            title="Behavior baseline",
            score=60,
            status="open",
            entity_type="user",
            entity_ref=entity_ref,
            channel="analytic",
            description=(
                f"{definition.label}: latest {profile['latest']:g} against a mean of {profile['mean']:g}."
            ),
        )
        db.add(alert)
        db.flush()
        db.add(BehaviorDeviation(
            entity_ref=entity_ref,
            indicator_key=definition.key,
            period_key=profile["latest_period"],
            latest=profile["latest"],
            mean=profile["mean"],
            deviation=profile["deviation"],
            alert_id=alert.id,
        ))
        created.append(alert.id)
    return created


def store_channel_events(db: Session, events: list[dict]) -> int:
    stored = 0
    users = set()
    for event in events:
        if db.query(ChannelEvent).filter_by(source_key=event["source_key"]).one_or_none() is not None:
            continue
        db.add(ChannelEvent(
            source_key=event["source_key"][:200],
            channel=event["channel"],
            user=event["user"][:120],
            occurred_at=event["occurred_at"][:40],
            action=event["action"][:40],
            reference=event["reference"][:120],
        ))
        remember_fact(
            db,
            source_key=f"channel:{event['source_key']}",
            source="channel",
            occurred_at=event["occurred_at"],
            entity_type="user",
            entity_ref=event["user"],
            name=f"channel_{event['channel']}",
            numeric_value=1,
            text_value=event["action"],
        )
        users.add(event["user"][:120])
        stored += 1
    for user in users:
        refresh_user(db, user)
    return stored


def unified_activity(db: Session, user: str) -> dict:
    grouped = {channel: [] for channel in CHANNELS}
    for row in db.query(ChannelEvent).filter_by(user=user).order_by(ChannelEvent.id.desc()).limit(200).all():
        grouped[row.channel].append({
            "occurred_at": row.occurred_at, "action": row.action, "reference": row.reference, "source": "channel",
        })
    for row in db.query(Fact).filter_by(entity_type="user", entity_ref=user).order_by(Fact.id.desc()).limit(200).all():
        if row.source == "channel":
            continue
        grouped["system"].append({
            "occurred_at": row.occurred_at, "action": row.name, "reference": row.text_value, "source": row.source,
        })
    for row in db.query(MailEvidence).filter_by(captured_by=user).order_by(MailEvidence.id.desc()).limit(50).all():
        grouped["email"].append({
            "occurred_at": row.occurred_at.isoformat(),
            "action": row.client,
            "reference": row.subject[:120],
            "source": "mail",
        })
    channels = {}
    for channel, events in grouped.items():
        ordered = sorted(events, key=lambda item: item["occurred_at"], reverse=True)[:50]
        channels[channel] = {"count": len(ordered), "events": ordered}
    return {"user": user, "channels": channels}
