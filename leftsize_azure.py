"""LeftSize's own Cloud Custodian filters for Azure resource types.

Registered on import; `leftsize_custodian.py` imports this module, so Azure scans must
run through that wrapper (see `custodian_command` in run.py).
"""

import logging
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError
from c7n.filters import Filter
from c7n.utils import type_schema
from c7n_azure.resources.appinsights import AzureAppInsights
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
