"""Cloud Custodian provider registration for Cloudflare.

c7n 0.9.48 has no plugin entry points: a provider registers when its module is
imported, and the stock `custodian` CLI only imports its built-in providers.
Run Custodian through `leftsize_custodian.py`, which imports this package first.
"""

from typing import Any

from c7n.provider import Provider, clouds
from c7n.registry import PluginRegistry

from .client import Session


@clouds.register("cloudflare")
class Cloudflare(Provider):
    display_name = "Cloudflare"
    resource_prefix = "cloudflare"
    resources = PluginRegistry("%s.resources" % resource_prefix)
    resource_map = {
        "cloudflare.zone": "c7n_cloudflare.resources.zone.Zone",
        "cloudflare.worker-script": "c7n_cloudflare.resources.worker.WorkerScript",
        "cloudflare.api-token": "c7n_cloudflare.resources.token.ApiToken",
        "cloudflare.r2-bucket": "c7n_cloudflare.resources.r2.R2Bucket",
        "cloudflare.account": "c7n_cloudflare.resources.account.Account",
        "cloudflare.certificate": "c7n_cloudflare.resources.certificate.Certificate",
        "cloudflare.domain": "c7n_cloudflare.resources.registrar.Domain",
        "cloudflare.zero-trust-user": "c7n_cloudflare.resources.zerotrust.ZeroTrustUser",
        "cloudflare.access-app": "c7n_cloudflare.resources.zerotrust.AccessApp",
        "cloudflare.access-service-token": "c7n_cloudflare.resources.zerotrust.AccessServiceToken",
        "cloudflare.tunnel": "c7n_cloudflare.resources.zerotrust.Tunnel",
        "cloudflare.lb-pool": "c7n_cloudflare.resources.loadbalancer.LoadBalancerPool",
    }

    def initialize(self, options: Any) -> Any:
        return options

    def initialize_policies(self, policy_collection: Any, options: Any) -> Any:
        return policy_collection

    def get_session_factory(self, options: Any) -> Any:
        return Session


resources = Cloudflare.resources
