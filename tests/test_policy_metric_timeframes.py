"""
Guards the `timeframe` of Azure metric filters in policies/.

c7n-azure's MetricFilter reads `timeframe` as hours
(start_time = end_time - timedelta(hours=timeframe)), so `timeframe: 7` with a
daily interval looks at 7 hours of data, not 7 days.
"""

from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

POLICIES_DIR = Path(__file__).parent.parent / 'policies'


def _metric_filters(node: Any) -> Iterator[dict]:
    if isinstance(node, dict):
        if node.get('type') == 'metric':
            yield node
        for value in node.values():
            yield from _metric_filters(value)
    elif isinstance(node, list):
        for value in node:
            yield from _metric_filters(value)


def _azure_metric_filters() -> list:
    found = []
    for path in sorted(POLICIES_DIR.glob('azure-*.yml')):
        for policy in (yaml.safe_load(path.read_text()) or {}).get('policies', []):
            for metric_filter in _metric_filters(policy.get('filters', [])):
                found.append(pytest.param(metric_filter, id=f"{policy['name']}:{metric_filter.get('metric')}"))
    return found


AZURE_METRIC_FILTERS = _azure_metric_filters()


def test_azure_metric_filters_found() -> None:
    assert AZURE_METRIC_FILTERS, 'expected Azure policies with metric filters'


@pytest.mark.parametrize('metric_filter', AZURE_METRIC_FILTERS)
def test_daily_interval_timeframe_is_whole_days_in_hours(metric_filter: dict) -> None:
    if metric_filter.get('interval') != 'P1D':
        pytest.skip('only daily-interval filters are checked')
    timeframe = metric_filter.get('timeframe')
    assert timeframe is not None, 'set timeframe explicitly (the c7n-azure default is 24 hours)'
    assert timeframe >= 24 and timeframe % 24 == 0, (
        f'timeframe {timeframe} is in hours; a daily interval needs whole days (e.g. 168 for 7 days)'
    )
