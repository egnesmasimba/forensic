CASE_TYPES = [
    "Employee Fraud",
    "Information Leakage",
    "Identity Theft",
    "Privileged IT User",
    "Account Takeover",
    "eBanking Fraud",
    "Phone Banking Fraud",
    "Other",
]

STATUSES = ["new", "in_review", "investigating", "escalated", "closed"]

STATUS_LABELS = {
    "new": "New",
    "in_review": "In review",
    "investigating": "Investigating",
    "escalated": "Escalated",
    "closed": "Closed",
}

ACTION_LABELS = {
    "in_review": "Start review",
    "investigating": "Begin investigation",
    "escalated": "Escalate",
    "closed": "Close case",
}

TRANSITIONS = {
    "new": ["in_review", "closed"],
    "in_review": ["investigating", "closed"],
    "investigating": ["escalated", "closed"],
    "escalated": ["investigating", "closed"],
    "closed": ["investigating"],
}

RISK_LEVELS = ["low", "medium", "high", "critical"]

ALERT_STATUSES = ["open", "linked", "dismissed", "suppressed"]

ENTITY_TYPES = ["user", "account", "customer", "other"]
