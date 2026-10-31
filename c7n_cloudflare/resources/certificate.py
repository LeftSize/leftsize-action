"""cloudflare.certificate: certificates you manage per zone: Cloudflare Origin CA
certificates (installed on the origin) and custom (uploaded) edge certificates.

Certificates Cloudflare issues and renews itself (Universal SSL, Advanced
Certificate Manager) are not included. PEM bodies and keys are never stored.

Token permission (read): SSL and Certificates.
"""

from typing import Any, Dict, List

from ..provider import resources
from ..query import QueryResourceManager, TypeInfo

CUSTOM_CERTIFICATE_PLANS = ("business", "enterprise")

KEEP = ("id", "hostnames", "hosts", "expires_on", "issuer", "status", "signature", "request_type",
        "requested_validity", "uploaded_on", "modified_on", "bundle_method", "type")


@resources.register("certificate")
class Certificate(QueryResourceManager):
    """Origin CA (`GET /certificates?zone_id=`) and custom certificates
    (`GET /zones/{id}/custom_certificates`) of every zone. `kind` is `origin-ca` or
    `custom`; `hostnames` lists the names the certificate covers."""

    class resource_type(TypeInfo):
        path = "/zones"
        kind = "certificate"
        date = "expires_on"
        default_report_fields = ("id", "kind", "hostnames", "expires_on", "zone.name")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_resources(self, session: Any) -> List[Dict[str, Any]]:
        certificates = []
        zones = list(session.paginate("/zones"))
        allowed = set(session.account_ids)
        for zone in zones:
            account = zone.get("account") or {}
            if allowed and account.get("id") not in allowed:
                continue
            sources = [("origin-ca", session.paginate("/certificates", zone_id=zone["id"]))]
            # Custom certificates need a Business or Enterprise plan; other zones refuse the call
            if (zone.get("plan") or {}).get("legacy_id") in CUSTOM_CERTIFICATE_PLANS:
                sources.append(("custom", session.paginate(f"/zones/{zone['id']}/custom_certificates")))
            for kind, items in sources:
                for cert in items:
                    record = {k: cert[k] for k in KEEP if k in cert}
                    record["kind"] = kind
                    record["hostnames"] = cert.get("hostnames") or cert.get("hosts") or []
                    record["zone"] = {"id": zone["id"], "name": zone.get("name")}
                    record["account"] = {"id": account.get("id"), "name": account.get("name")}
                    certificates.append(record)
        return certificates
