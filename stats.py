#!/usr/bin/env python3
"""
LeftSize Stats - Python module for fetching and displaying repository statistics
"""

import os
import json
from typing import Dict, Any, Optional
import requests
import structlog

logger = structlog.get_logger()


def fetch_stats(
    backend_url: str,
    installation_id: str,
    repository_token: str,
    owner: str,
    repo: str,
    period: str = '30d',
    format: str = 'markdown',
    report: str = 'summary'
) -> Dict[str, Any]:
    """
    Fetch statistics from the LeftSize backend API

    The API returns JSON; the markdown report is rendered here.

    Returns a dict with:
    - success: bool
    - report: str (markdown or json content)
    - stats: dict (raw stats data)
    - error: str (if success is False)
    """

    url = f"{backend_url}/api/stats/{installation_id}/{owner}/{repo}"
    params = {'period': period}
    headers = {
        'Authorization': f'Bearer {repository_token}',
        'User-Agent': 'LeftSize-Action/1.0',
        'Accept': 'application/json'
    }

    logger.info(
        "Fetching stats from backend",
        url=url,
        period=period,
        format=format,
        report=report
    )

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        stats_data = response.json()

        if format == 'markdown':
            content = render_markdown_report(stats_data, f"{owner}/{repo}", report)
        else:
            content = json.dumps(stats_data, indent=2, default=str)
        return {
            'success': True,
            'report': content,
            'stats': stats_data
        }

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else 'unknown'
        logger.error("HTTP error fetching stats", status_code=status_code, error=str(e))
        return {
            'success': False,
            'error': f"HTTP {status_code}: {str(e)}",
            'report': None,
            'stats': None
        }
    except requests.exceptions.RequestException as e:
        logger.error("Request error fetching stats", error=str(e))
        return {
            'success': False,
            'error': str(e),
            'report': None,
            'stats': None
        }
    except Exception as e:
        logger.error("Unexpected error fetching stats", error=str(e))
        return {
            'success': False,
            'error': str(e),
            'report': None,
            'stats': None
        }


def _primary_amount(entries: Any) -> tuple[float, str]:
    """Largest amount in a [{Currency, TotalAmount}] list, with its currency."""
    if not entries:
        return 0.0, 'USD'
    best = max(entries, key=lambda e: e.get('TotalAmount') or 0)
    return float(best.get('TotalAmount') or 0), best.get('Currency') or 'USD'


def _format_amount(amount: float) -> str:
    """Round to cents; whole amounts without a decimal part (50, not 50.0)."""
    value = round(amount, 2)
    return str(int(value)) if value == int(value) else str(value)


def extract_key_metrics(stats: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract key metrics from stats response for GitHub Action outputs
    """
    if not stats:
        return {
            'fix_ratio': '0',
            'potential_savings': '0',
            'realized_savings': '0',
            'currency': 'USD',
            'currency_symbol': '$'
        }

    total = stats.get('TotalFindings') or 0
    by_status = {s.get('Status'): s.get('Count') or 0 for s in stats.get('FindingsByStatus') or []}
    resolved = total - by_status.get('open', 0)
    potential, currency = _primary_amount(stats.get('EstimatedSavings'))
    realized = next((float(e.get('TotalAmount') or 0) for e in stats.get('RealizedSavings') or []
                     if e.get('Currency') == currency), 0.0)

    return {
        'fix_ratio': str(round(resolved / total * 100, 1)) if total else '0',
        'potential_savings': _format_amount(potential),
        'realized_savings': _format_amount(realized),
        'currency': currency,
        'currency_symbol': get_currency_symbol(currency)
    }


PERIOD_LABELS = {'7d': 'last 7 days', '30d': 'last 30 days', '90d': 'last 90 days', 'all': 'all time'}


def render_markdown_report(stats: Dict[str, Any], repository: str, report: str = 'summary') -> str:
    """Render the stats response as a markdown report.

    summary:   key numbers; detailed: plus breakdowns by status and cloud;
    executive: two lines for status updates.
    """
    metrics = extract_key_metrics(stats)
    symbol = metrics['currency_symbol']
    period = PERIOD_LABELS.get(stats.get('Period') or 'all', stats.get('Period') or 'all time')
    total = stats.get('TotalFindings') or 0
    open_issues = stats.get('OpenIssues') or 0
    savings = f"{symbol}{float(metrics['potential_savings']):,.2f}"
    last_scan = stats.get('LastScanAt') or 'never'

    if report == 'executive':
        return (
            f"## LeftSize: {repository}\n\n"
            f"**{open_issues}** open LeftSize issues, **{savings}/month** in estimated savings "
            f"({total} findings, {period}).\n"
        )

    lines = [
        f"# LeftSize Report: {repository}",
        "",
        f"_Findings seen in the {period}. Last scan: {last_scan}._" if period != 'all time'
        else f"_All findings. Last scan: {last_scan}._",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Findings | {total} |",
        f"| Open LeftSize issues | {open_issues} |",
        f"| Estimated monthly savings | {savings} |",
    ]
    for entry in stats.get('EstimatedSavings') or []:
        if entry.get('Currency') != metrics['currency']:
            lines.append(f"| Estimated monthly savings ({entry.get('Currency')}) | "
                         f"{float(entry.get('TotalAmount') or 0):,.2f} |")

    if report == 'detailed':
        by_status = stats.get('FindingsByStatus') or []
        by_provider = stats.get('FindingsByProvider') or []
        if by_status:
            lines += ["", "## Findings by status", "", "| Status | Findings |", "|---|---|"]
            lines += [f"| {s.get('Status')} | {s.get('Count')} |" for s in by_status]
        if by_provider:
            lines += ["", "## Findings by cloud", "", "| Cloud | Findings |", "|---|---|"]
            lines += [f"| {str(p.get('Provider')).upper()} | {p.get('Count')} |" for p in by_provider]

    lines += ["", "Open issues have the `leftsize` label; each one explains how to fix it."]
    return "\n".join(lines) + "\n"


def get_currency_symbol(currency_code: str) -> str:
    """
    Get currency symbol for a given currency code
    """
    symbols = {
        'EUR': '€',
        'GBP': '£',
        'JPY': '¥',
        'CHF': 'CHF',
        'CAD': 'CA$',
        'AUD': 'A$',
        'SEK': 'kr',
        'NOK': 'kr',
        'DKK': 'kr',
        'PLN': 'zł',
        'CZK': 'Kč',
        'HUF': 'Ft',
        'INR': '₹',
        'BRL': 'R$',
        'MXN': 'MX$',
        'ZAR': 'R',
        'SGD': 'S$',
        'HKD': 'HK$',
        'NZD': 'NZ$',
        'KRW': '₩',
        'USD': '$'
    }
    return symbols.get(currency_code.upper() if currency_code else 'USD', '$')


def get_repo_info() -> tuple[str, str]:
    """
    Get repository owner and name from GitHub environment
    
    Returns (owner, repo) tuple
    """
    github_repository = os.getenv('GITHUB_REPOSITORY', '')
    if '/' in github_repository:
        parts = github_repository.split('/', 1)
        return parts[0], parts[1]
    return '', ''


def stats_main() -> int:
    """
    Stats mode entry point - reads from environment variables, fetches stats, sets outputs
    
    Returns exit code (0 for success, 1 for failure)
    """
    
    # Read configuration from environment
    verbose = os.getenv('LEFTSIZE_VERBOSE', 'false').lower() == 'true'
    backend_url = os.getenv('LEFTSIZE_BACKEND_URL', 'https://api.leftsize.com')
    installation_id = os.getenv('LEFTSIZE_INSTALLATION_ID', '')
    repository_token = os.getenv('LEFTSIZE_REPOSITORY_TOKEN', '')
    period = os.getenv('LEFTSIZE_PERIOD', '30d')
    format = os.getenv('LEFTSIZE_FORMAT', 'markdown')
    report = os.getenv('LEFTSIZE_REPORT', 'summary')
    
    # Shared with scan mode: logging setup and the LeftSize-host check for the URL
    # that receives the repository token
    from run import configure_logging, validate_backend_url
    configure_logging(verbose)
    
    logger.info("LeftSize Stats mode starting", version="1.0.0")
    
    if not validate_backend_url(backend_url):
        logger.error("Invalid backend-url. Must be an https URL on a LeftSize domain.")
        set_github_output('report', '')
        return 1
    
    # Validate required inputs
    if not installation_id:
        logger.error("Missing required input: installation-id")
        set_github_output('report', '')
        return 1
    
    if not repository_token:
        logger.error("Missing required input: repository-token")
        set_github_output('report', '')
        return 1
    
    # Validate period
    valid_periods = ['7d', '30d', '90d', 'all']
    if period not in valid_periods:
        logger.error("Invalid period. Must be one of: 7d, 30d, 90d, all", period=period)
        set_github_output('report', '')
        return 1
    
    # Validate format
    valid_formats = ['json', 'markdown']
    if format not in valid_formats:
        logger.error("Invalid format. Must be one of: json, markdown", format=format)
        set_github_output('report', '')
        return 1
    
    # Validate report type
    valid_reports = ['summary', 'detailed', 'executive']
    if report not in valid_reports:
        logger.error("Invalid report type. Must be one of: summary, detailed, executive", report=report)
        set_github_output('report', '')
        return 1
    
    # Get repository info from GitHub environment
    owner, repo = get_repo_info()
    if not owner or not repo:
        logger.error("Could not determine repository from GITHUB_REPOSITORY environment variable")
        set_github_output('report', '')
        return 1
    
    logger.info(
        "Fetching stats",
        owner=owner,
        repo=repo,
        period=period,
        format=format,
        report=report
    )
    
    # Fetch stats from backend
    result = fetch_stats(
        backend_url=backend_url,
        installation_id=installation_id,
        repository_token=repository_token,
        owner=owner,
        repo=repo,
        period=period,
        format=format,
        report=report
    )
    
    if not result['success']:
        logger.error("Failed to fetch stats", error=result.get('error', 'Unknown error'))
        set_github_output('report', '')
        set_github_output('stats-json', '{}')
        set_github_output('fix-ratio', '0')
        set_github_output('potential-savings', '0')
        set_github_output('realized-savings', '0')
        set_github_output('currency', 'USD')
        set_github_output('currency-symbol', '$')
        return 1
    
    # Set GitHub Action outputs
    report_content = result.get('report', '')
    set_github_output('report', report_content)
    
    # Raw stats come back for both formats
    stats_data = result.get('stats')
    if stats_data:
        set_github_output('stats-json', json.dumps(stats_data, default=str))
        metrics = extract_key_metrics(stats_data)
        set_github_output('fix-ratio', metrics['fix_ratio'])
        set_github_output('potential-savings', metrics['potential_savings'])
        set_github_output('realized-savings', metrics['realized_savings'])
        set_github_output('currency', metrics['currency'])
        set_github_output('currency-symbol', metrics['currency_symbol'])
    else:
        set_github_output('stats-json', '{}')
        set_github_output('fix-ratio', '0')
        set_github_output('potential-savings', '0')
        set_github_output('realized-savings', '0')
        set_github_output('currency', 'USD')
        set_github_output('currency-symbol', '$')
    
    # Print summary to GitHub Actions job summary
    print_stats_summary(report_content, format)
    
    logger.info("LeftSize Stats completed successfully")
    return 0


def set_github_output(name: str, value: str):
    """Set GitHub Actions output"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if github_output:
        # Handle multiline values using heredoc syntax
        if '\n' in value:
            import uuid
            delimiter = f"EOF_{uuid.uuid4().hex[:8]}"
            with open(github_output, 'a') as f:
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            with open(github_output, 'a') as f:
                f.write(f"{name}={value}\n")
    else:
        # Fallback for testing (deprecated syntax)
        if '\n' in value:
            # Can't easily handle multiline in old syntax
            print(f"::set-output name={name}::[multiline content]")
        else:
            print(f"::set-output name={name}::{value}")


def print_stats_summary(report_content: str, format: str):
    """Print stats to GitHub Actions job summary"""
    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    
    if format == 'markdown':
        summary = report_content
    else:
        # For JSON format, create a simple markdown summary
        summary = f"""# LeftSize Statistics Report

```json
{report_content[:5000]}{"..." if len(report_content) > 5000 else ""}
```
"""
    
    if github_step_summary:
        with open(github_step_summary, 'a') as f:
            f.write(summary)
    else:
        print(summary)


if __name__ == "__main__":
    import sys
    sys.exit(stats_main())
