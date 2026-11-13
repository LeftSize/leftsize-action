"""LeftSize's own Cloud Custodian resources and filters for AWS.

Registered on import; `leftsize_custodian.py` imports this module (AWS scans run through
that wrapper, see `custodian_command` in run.py).

- `aws.bedrock-model-usage`: the Bedrock models a Region served in the last N days, from
  CloudWatch (namespace AWS/Bedrock, metric Invocations, dimension ModelId). One resource
  per base model; calls through cross-Region inference profiles (us., eu., global., ...)
  count towards the model they route to.
- `bedrock-end-of-life` filter: the models in use that AWS lists with an end-of-life date
  for the scanned Region (the table is the policy's, so it can be reviewed with it).
"""

import datetime
import logging
import re
from typing import Any, Dict, Iterable, List, Optional

from c7n.filters import Filter
from c7n.manager import resources
from c7n.query import DescribeSource, QueryResourceManager, TypeInfo
from c7n.resources.resource_map import ResourceMap
from c7n.utils import local_session, type_schema

log = logging.getLogger('custodian.leftsize.aws')

USAGE_DAYS = 14
END_OF_LIFE = 'c7n:end-of-life'
# Cross-Region inference profile prefixes: "us.anthropic.claude-..." routes to the model
# "anthropic.claude-..."
PROFILE_PREFIX = re.compile(r'^(?:us|eu|apac|jp|au|ca|us-gov|global)\.(?=[a-z0-9-]+\.)')
# An ARN as ModelId (provisioned throughput, imported or custom models) isn't a foundation
# model this rule can date
ARN = re.compile(r'^arn:')


def base_model_id(model_id: str) -> Optional[str]:
    """The foundation model a CloudWatch ModelId stands for; None for ARNs."""
    if not model_id or ARN.match(model_id):
        return None
    return PROFILE_PREFIX.sub('', model_id)


def model_usage(client: Any, region: str, days: int = USAGE_DAYS,
                now: Optional[datetime.datetime] = None) -> List[Dict[str, Any]]:
    """Invocations per foundation model in this Region over the last `days` days."""
    metrics = []
    for page in client.get_paginator('list_metrics').paginate(Namespace='AWS/Bedrock', MetricName='Invocations'):
        for metric in page.get('Metrics', []):
            dims = metric.get('Dimensions') or []
            # Only the per-model series ([ModelId]); other dimension sets repeat the counts
            if len(dims) == 1 and dims[0].get('Name') == 'ModelId':
                metrics.append(dims[0]['Value'])
    end = now or datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(days=days)
    totals: Dict[str, Dict[str, Any]] = {}
    for i in range(0, len(metrics), 500):
        chunk = metrics[i:i + 500]
        queries = [{
            'Id': f'm{n}',
            'MetricStat': {
                'Metric': {'Namespace': 'AWS/Bedrock', 'MetricName': 'Invocations',
                           'Dimensions': [{'Name': 'ModelId', 'Value': model_id}]},
                'Period': days * 86400,
                'Stat': 'Sum',
            },
        } for n, model_id in enumerate(chunk)]
        token = None
        while True:
            kwargs = {'MetricDataQueries': queries, 'StartTime': start, 'EndTime': end}
            if token:
                kwargs['NextToken'] = token
            response = client.get_metric_data(**kwargs)
            for result in response.get('MetricDataResults', []):
                model_id = chunk[int(result['Id'][1:])]
                count = sum(result.get('Values') or [])
                base = base_model_id(model_id)
                if not base or count <= 0:
                    continue
                entry = totals.setdefault(base, {'modelId': base, 'invocations': 0, 'invokedAs': []})
                entry['invocations'] += int(count)
                if model_id not in entry['invokedAs']:
                    entry['invokedAs'].append(model_id)
            token = response.get('NextToken')
            if not token:
                break
    for entry in totals.values():
        entry['Region'] = region
        entry['Name'] = entry['modelId']
        entry['days'] = days
        # The foundation model's ARN (no account): one finding per model and Region
        entry['Arn'] = f"arn:aws:bedrock:{region}::foundation-model/{entry['modelId']}"
    return sorted(totals.values(), key=lambda e: e['modelId'])


class DescribeBedrockModelUsage(DescribeSource):

    def resources(self, query: Any = None) -> List[Dict[str, Any]]:
        client = local_session(self.manager.session_factory).client('cloudwatch', region_name=self.manager.config.region)
        return model_usage(client, self.manager.config.region)

    def get_resources(self, ids: Iterable[str], cache: bool = True) -> List[Dict[str, Any]]:
        wanted = set(ids)
        return [r for r in self.resources() if r['modelId'] in wanted]

    def augment(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return resources


@resources.register('bedrock-model-usage')
class BedrockModelUsage(QueryResourceManager):
    """Bedrock foundation models invoked in a Region in the last 14 days (CloudWatch)."""

    class resource_type(TypeInfo):
        # Regions where Bedrock exists; the calls themselves go to CloudWatch
        service = 'bedrock'
        id = 'modelId'
        name = 'modelId'
        arn = 'Arn'
        arn_type = 'foundation-model'
        global_resource = False
        cfn_type = None
        permissions_augment = ()

    source_mapping = {'describe': DescribeBedrockModelUsage}

    @classmethod
    def get_permissions(cls):
        return ('cloudwatch:ListMetrics', 'cloudwatch:GetMetricData')


def _date(value: str) -> datetime.date:
    return datetime.date.fromisoformat(str(value))


@BedrockModelUsage.filter_registry.register('bedrock-end-of-life')
class BedrockEndOfLifeFilter(Filter):
    """Models in use that reach end of life in the scanned Region.

    Each entry names a model id, the Regions its end-of-life date covers and the date.
    The earliest matching date is stored as `c7n:end-of-life` ({date, legacyDate,
    extendedAccess}) for the issue.

    :example:

    .. code-block:: yaml

        filters:
          - type: bedrock-end-of-life
            models:
              - {id: anthropic.claude-opus-4-1-20250805-v1:0, regions: [us-east-1], eol: '2027-01-08'}
    """

    schema = type_schema(
        'bedrock-end-of-life',
        required=['models'],
        models={'type': 'array', 'items': {
            'type': 'object',
            'required': ['id', 'regions', 'eol'],
            'additionalProperties': False,
            'properties': {
                'id': {'type': 'string'},
                'regions': {'type': 'array', 'items': {'type': 'string'}},
                'eol': {'type': 'string'},
                'legacy': {'type': 'string'},
                'extended_access': {'type': 'string'},
            },
        }},
    )

    def validate(self):
        for entry in self.data.get('models', []):
            _date(entry['eol'])
        return self

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        matched = []
        for resource in resources:
            region = resource.get('Region') or self.manager.config.region
            entries = [e for e in self.data['models'] if e['id'] == resource.get('modelId') and region in e['regions']]
            if not entries:
                continue
            entry = min(entries, key=lambda e: e['eol'])
            resource[END_OF_LIFE] = {
                'date': entry['eol'],
                'legacyDate': entry.get('legacy'),
                'extendedAccess': entry.get('extended_access'),
            }
            matched.append(resource)
        return matched


# Custodian checks this static map before its registry (get_resource_class), so policies
# with `resource: aws.bedrock-model-usage` validate
ResourceMap.setdefault('aws.bedrock-model-usage', 'leftsize_aws.BedrockModelUsage')
