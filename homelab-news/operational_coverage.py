"""Compatibility imports for packaged newsroom coverage policy."""

from homelab_news.newsroom.coverage import (
    build_operational_alerts_article,
    issue_escalation_reason,
    select_news_issues,
)

__all__ = [
    "build_operational_alerts_article",
    "issue_escalation_reason",
    "select_news_issues",
]
