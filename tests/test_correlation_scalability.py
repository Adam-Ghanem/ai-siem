from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from backend.correlation import correlate
from backend.models import Alert


def _chain_alert(index: int, timestamp: datetime) -> Alert:
    asset = user = src_ip = None
    phase = index % 3
    if index == 0:
        asset = 'entity-0'
    elif phase == 1:
        asset = f'entity-{index - 1}'
        user = f'entity-{index}'
    elif phase == 2:
        user = f'entity-{index - 1}'
        src_ip = f'entity-{index}'
    else:
        src_ip = f'entity-{index - 1}'
        asset = f'entity-{index}'

    return Alert(
        alert_id=f'alert-{index}',
        rule_id='R-CHAIN',
        title='Chained activity',
        severity='medium',
        confidence=0.9,
        tactic='Discovery',
        technique='T0000',
        timestamp=timestamp,
        asset=asset,
        user=user,
        src_ip=src_ip,
        event_ids=[f'event-{index}'],
        recommended_action='Investigate',
    )


def test_correlation_avoids_quadratic_relation_scans_for_transitive_chain():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alerts = [_chain_alert(i, base + timedelta(seconds=i)) for i in range(120)]

    from backend import correlation

    original_rel = correlation._rel
    calls = 0

    def counted_rel(a, b, window_seconds):
        nonlocal calls
        calls += 1
        return original_rel(a, b, window_seconds)

    with patch('backend.correlation._rel', side_effect=counted_rel):
        incidents = correlate(alerts)

    assert len(incidents) == 1
    assert incidents[0].related_alert_ids == [alert.alert_id for alert in alerts]
    assert calls <= len(alerts) * 3
