"""LeftSize's own Cloud Custodian filters for Azure resource types.

Registered on import; `leftsize_custodian.py` imports this module, so Azure scans must
run through that wrapper (see `custodian_command` in run.py).
"""

import logging
import re
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError
from azure.core.rest import HttpRequest
from c7n.filters import Filter
from c7n.utils import type_schema
from c7n_azure.resources.appinsights import AzureAppInsights
from c7n_azure.resources.cognitive_service import CognitiveService
from c7n_azure.utils import ResourceIdParser

QUERY_API_KEYS = 'c7n:query-api-keys'

# run.py forwards this logger's warnings to the job log and the scan problems
log = logging.getLogger('custodian.leftsize.azure')


def is_query_key(linked_read_properties: Optional[List[str]]) -> bool:
    """An API key that can query telemetry has `.../components/<name>/api` among its read
    properties. Keys that only authenticate the Live Metrics control channel
    (`.../agentconfig`) or only write annotations don't."""
    return any(p.lower().rstrip('/').endswith('/api') for p in (linked_read_properties or []))


@AzureAppInsights.filter_registry.register('query-api-keys')
class QueryApiKeysFilter(Filter):
    """Application Insights components with at least one API key that can query data.

    Lists the component's API keys (`Microsoft.Insights/components/ApiKeys/read`, part of
    Reader). The list holds key names, dates and permissions, never the key itself.
    Matching keys are stored as `c7n:query-api-keys` ({name, createdDate}) for the issue.

    A component whose keys can't be read (a custom role without ApiKeys/read, a component
    deleted since the listing) is skipped with a warning, so it doesn't cost the other
    components their findings. If no component's keys can be read, the error is raised,
    so a missing permission shows up as a failed rule instead of zero findings.

    :example:

    .. code-block:: yaml

        policies:
          - name: appinsights-query-api-keys
            resource: azure.app-insights
            filters:
              - type: query-api-keys
    """

    schema = type_schema('query-api-keys')

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        client = self.manager.get_client()
        matched = []
        errors: List[HttpResponseError] = []
        for resource in resources:
            # The raw listing has no resourceGroup field; take it from the id
            group = ResourceIdParser.get_resource_group(resource['id'])
            try:
                keys = [k for k in client.api_keys.list(group, resource['name'])
                        if is_query_key(k.linked_read_properties)]
            except HttpResponseError as error:
                log.warning('Could not list the API keys of %s (HTTP %s): %s',
                            resource['id'], error.status_code, error.reason)
                errors.append(error)
                continue
            if keys:
                resource[QUERY_API_KEYS] = [{'name': k.name, 'createdDate': k.created_date} for k in keys]
                matched.append(resource)
        if resources and len(errors) == len(resources):
            raise errors[0]
        return matched


# --- Azure OpenAI model retirements ---------------------------------------------------

RETIRING_DEPLOYMENTS = 'c7n:retiring-deployments'
# Deployment types Microsoft upgrades to the replacement model at retirement, unless the
# deployment's versionUpgradeOption is NoAutoUpgrade. Provisioned and Batch deployments
# never are.
AUTO_UPGRADED_SKUS = {'standard', 'globalstandard', 'datazonestandard'}
# Fine-tuned deployments name their base model and version: "gpt-4o-mini-2024-07-18.ft-<id>"
FINE_TUNED = re.compile(r'^(?P<model>.+)-(?P<version>\d{4}-\d{2}-\d{2})\.ft-', re.I)
DEPLOYMENTS_API_VERSION = '2024-10-01'


def retiring_deployment(deployment: Dict[str, Any], table: Dict[tuple, Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """The deployment as an entry for the issue when it stops working at a listed
    retirement: a retiring base model on a deployment type Microsoft doesn't upgrade (or
    with auto-upgrade turned off), or a fine-tuned model of a retiring base."""
    props = deployment.get('properties') or {}
    model = props.get('model') or {}
    name, version = str(model.get('name') or ''), str(model.get('version') or '')
    sku = str((deployment.get('sku') or {}).get('name') or '')
    upgrade = props.get('versionUpgradeOption') or None
    entry = {'deployment': deployment.get('name'), 'model': name, 'version': version, 'sku': sku,
             'versionUpgradeOption': upgrade}
    fine_tuned = FINE_TUNED.match(name)
    if fine_tuned:
        retirement = table.get((fine_tuned.group('model').lower(), fine_tuned.group('version')))
        if retirement and retirement.get('fine_tuned_date'):
            return {**entry, 'baseModel': fine_tuned.group('model'), 'baseVersion': fine_tuned.group('version'),
                    'retires': retirement['fine_tuned_date'], 'fineTuned': True}
        return None
    retirement = table.get((name.lower(), version))
    if not retirement or not retirement.get('date'):
        return None
    if sku.lower() in AUTO_UPGRADED_SKUS and upgrade != 'NoAutoUpgrade':
        return None  # Microsoft upgrades it to the replacement model
    return {**entry, 'retires': retirement['date'], 'fineTuned': False}


@CognitiveService.filter_registry.register('retiring-model-deployments')
class RetiringModelDeploymentsFilter(Filter):
    """Azure OpenAI / Foundry accounts with deployments that stop working when their model
    version retires.

    Lists each account's deployments (`Microsoft.CognitiveServices/accounts/deployments/read`,
    part of Reader) and matches them against the policy's `retirements` table. Standard,
    Global Standard and Data Zone Standard deployments are upgraded by Microsoft, so they only
    count with `versionUpgradeOption: NoAutoUpgrade`; Provisioned and Batch deployments
    always count, and so do fine-tuned deployments of a listed base model (their own date).
    Matches are stored as `c7n:retiring-deployments`, earliest first.

    An account whose deployments can't be read is skipped with a warning; if none can be
    read, the error is raised so a missing permission shows up as a failed rule.

    :example:

    .. code-block:: yaml

        filters:
          - type: retiring-model-deployments
            retirements:
              - {model: gpt-4o, version: '2024-05-13', date: '2027-01-14'}
              - {model: gpt-4o-mini, version: '2024-07-18', date: '2027-04-14', fine_tuned_date: '2027-10-01'}
    """

    schema = type_schema(
        'retiring-model-deployments',
        required=['retirements'],
        retirements={'type': 'array', 'items': {
            'type': 'object',
            'required': ['model', 'version'],
            'additionalProperties': False,
            'properties': {
                'model': {'type': 'string'},
                'version': {'type': 'string'},
                'date': {'type': 'string'},
                'fine_tuned_date': {'type': 'string'},
            },
        }},
    )

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        table = {(r['model'].lower(), str(r['version'])): r for r in self.data['retirements']}
        client = self.manager.get_client()
        matched = []
        errors: List[HttpResponseError] = []
        for resource in resources:
            try:
                deployments = list_deployments(client, resource['id'])
            except HttpResponseError as error:
                log.warning('Could not list the deployments of %s (HTTP %s): %s',
                            resource['id'], error.status_code, error.reason)
                errors.append(error)
                continue
            hits = [h for h in (retiring_deployment(d, table) for d in deployments) if h]
            if hits:
                resource[RETIRING_DEPLOYMENTS] = sorted(hits, key=lambda h: (h['retires'], h['deployment'] or ''))
                matched.append(resource)
        if resources and len(errors) == len(resources):
            raise errors[0]
        return matched


def list_deployments(client: Any, account_id: str) -> List[Dict[str, Any]]:
    """An account's deployments, through the management client's authenticated pipeline
    (the installed SDK predates the deployments operations)."""
    url: Optional[str] = (f"{client._client._base_url.rstrip('/')}{account_id}/deployments"
                          f"?api-version={DEPLOYMENTS_API_VERSION}")
    deployments: List[Dict[str, Any]] = []
    while url:
        response = client._client.send_request(HttpRequest('GET', url))
        response.raise_for_status()
        body = response.json()
        deployments.extend(body.get('value') or [])
        url = body.get('nextLink')
    return deployments
