import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.models import Alert, SitePolicy, SiteRule, SiteVisit
from app.observations import require_timestamp

CATEGORIES = (
    "Business",
    "Search",
    "News",
    "Email",
    "Social networking",
    "Instant messaging",
    "Streaming media",
    "File sharing",
    "Cloud storage",
    "Shopping",
    "Banking",
    "Finance",
    "Gambling",
    "Games",
    "Adult",
    "Malicious",
    "Phishing",
    "Hacking",
    "Proxies and anonymizers",
    "Job search",
    "Education",
    "Reference",
    "Health",
    "Government",
    "Travel",
    "Sports",
    "Entertainment",
    "Forums",
    "Blogs",
    "Advertising",
    "Software downloads",
    "Webmail",
    "Collaboration",
    "Developer tools",
    "Remote access",
    "Weapons",
    "Drugs",
    "Hate",
    "Personal sites",
    "Dating",
    "Alcohol and tobacco",
    "Uncategorized",
)

DENIED_DEFAULT = {
    "Adult",
    "Malicious",
    "Phishing",
    "Gambling",
    "Hacking",
    "Proxies and anonymizers",
    "Weapons",
    "Drugs",
}

HOST_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def hostname_of(value: str) -> str:
    text = value.strip()
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not HOST_NAME.fullmatch(host) or len(host) > 253:
        raise ValueError("Enter a website hostname")
    return host


class VisitRecord(BaseModel):
    visit_id: str = Field(min_length=1, max_length=80)
    occurred_at: str
    user: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=1, max_length=300)
    seconds: int = Field(ge=0, le=86400)

    @field_validator("visit_id", "user")
    @classmethod
    def trimmed(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("A value is required")
        return text

    @field_validator("occurred_at")
    @classmethod
    def stamped(cls, value: str) -> str:
        return require_timestamp(value)

    @field_validator("url")
    @classmethod
    def host(cls, value: str) -> str:
        return hostname_of(value)


def seed_site_policy(db: Session) -> None:
    found = {row.category for row in db.query(SitePolicy).all()}
    for category in CATEGORIES:
        if category not in found:
            db.add(SitePolicy(category=category, denied=category in DENIED_DEFAULT))
    db.commit()


def category_for(host: str, rules: list[SiteRule]) -> str:
    best = None
    for rule in rules:
        if host == rule.host or host.endswith("." + rule.host):
            if best is None or len(rule.host) > len(best.host):
                best = rule
    return best.category if best else "Uncategorized"


def denied_categories(db: Session) -> set[str]:
    return {row.category for row in db.query(SitePolicy).filter_by(denied=True).all()}


def store_visits(db: Session, visits: list[VisitRecord], source: str, username: str) -> dict:
    from fastapi import HTTPException

    rules = db.query(SiteRule).all()
    denied = denied_categories(db)
    accepted = duplicates = 0
    fresh: list[SiteVisit] = []
    try:
        for visit in visits:
            existing = db.query(SiteVisit).filter_by(source=source, visit_id=visit.visit_id).one_or_none()
            category = category_for(visit.url, rules)
            if existing is not None:
                same = (
                    existing.occurred_at == visit.occurred_at
                    and existing.user == visit.user
                    and existing.host == visit.url
                    and existing.seconds == visit.seconds
                    and existing.category == category
                )
                if not same:
                    raise HTTPException(409, f"Visit {visit.visit_id} already exists with different data")
                duplicates += 1
                continue
            row = SiteVisit(
                source=source,
                visit_id=visit.visit_id,
                occurred_at=visit.occurred_at,
                user=visit.user,
                host=visit.url,
                seconds=visit.seconds,
                category=category,
                imported_by=username,
            )
            db.add(row)
            fresh.append(row)
            accepted += 1
        groups: dict[tuple[str, str], list[SiteVisit]] = {}
        for row in fresh:
            if row.category in denied:
                groups.setdefault((row.user, row.category), []).append(row)
        alert_ids = []
        for (user, category), rows in groups.items():
            seconds = sum(item.seconds for item in rows)
            alert = Alert(
                title=f"Website category: {category}",
                score=70,
                status="open",
                entity_type="user",
                entity_ref=user,
                channel="web",
                description=(
                    f"Rule: website-category. User: {user}. Category: {category}. "
                    f"Visits: {len(rows)}. Seconds: {seconds}."
                ),
            )
            db.add(alert)
            db.flush()
            alert_ids.append(alert.id)
        from app.analytics import evaluate_rules, note_visit
        for row in fresh:
            note_visit(db, row)
        alert_ids.extend(evaluate_rules(db, {("user", row.user) for row in fresh}))
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    return {"accepted": accepted, "duplicates": duplicates, "alerts_created": len(alert_ids), "alert_ids": alert_ids}


def category_report(db: Session) -> list[dict]:
    rows = db.query(SiteVisit).all()
    grouped: dict[str, dict] = {}
    for row in rows:
        item = grouped.setdefault(row.category, {"category": row.category, "visits": 0, "seconds": 0, "users": set()})
        item["visits"] += 1
        item["seconds"] += row.seconds
        item["users"].add(row.user)
    report = []
    for item in grouped.values():
        report.append({
            "category": item["category"],
            "visits": item["visits"],
            "seconds": item["seconds"],
            "users": len(item["users"]),
        })
    return sorted(report, key=lambda item: (-item["seconds"], item["category"]))


def access_patterns(db: Session) -> list[dict]:
    denied = denied_categories(db)
    grouped: dict[str, dict] = {}
    for row in db.query(SiteVisit).all():
        item = grouped.setdefault(row.user, {"user": row.user, "visits": 0, "seconds": 0, "denied_visits": 0, "by_category": {}})
        item["visits"] += 1
        item["seconds"] += row.seconds
        item["by_category"][row.category] = item["by_category"].get(row.category, 0) + row.seconds
        if row.category in denied:
            item["denied_visits"] += 1
    patterns = []
    for item in grouped.values():
        primary = max(item["by_category"], key=lambda name: (item["by_category"][name], name))
        patterns.append({
            "user": item["user"],
            "visits": item["visits"],
            "seconds": item["seconds"],
            "categories": sorted(item["by_category"]),
            "primary_category": primary,
            "denied_visits": item["denied_visits"],
        })
    return sorted(patterns, key=lambda item: item["user"])
