"""Cloudflare provider for Cloud Custodian (read-only), used by LeftSize.

Importing this package registers the `cloudflare` provider and its resources.
"""

from . import provider  # noqa: F401  registers the provider
from .resources import account, certificate, loadbalancer, r2, registrar, token, worker, zerotrust, zone  # noqa: F401  registers the resources
