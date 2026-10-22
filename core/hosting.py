"""Hosting/CDN attribution: who a row actually belongs to.

An asset that sits on a CDN or a cloud provider carries *that provider's* certificate, filing and
organization fields, not the target's, so it must not be used as a seed for ownership pivots and it
must be visible as such in the briefing. Measured on a real run: a Cloudflare-fronted host reported
four edge addresses and the briefing had to explain that the origin was masked.
"""

from __future__ import annotations

import re
from typing import Any

# Matched against `org`, `isp`, `as_org` and `server`: the fields an engine uses to name the
# network operator. Kept to providers that are common in Chinese asset collections.
HOSTING_PROVIDER_PATTERN = re.compile(
    r"(?:cloudflare|akamai|fastly|incapsula|imperva|sucuri|stackpath|edgecast|"
    r"amazon|aws|google cloud|gcp|microsoft|azure|oracle cloud|ibm cloud|"
    r"digitalocean|linode|vultr|hetzner|ovh|contabo|scaleway|leaseweb|choopa|"
    r"alibaba|aliyun|ali cloud|tencent|huawei cloud|baidu cloud|ucloud|kingsoft|"
    r"阿里云|腾讯云|华为云|百度云|金山云|青云|ucloud|美团云|京东云|"
    r"\bcdn\b|content delivery)",
    re.IGNORECASE,
)


def hosting_provider(values: dict[str, Any]) -> str:
    """Name of the hosting/CDN provider a row sits behind, or "" when none is recognized.

    Only the network-owner fields are inspected: a page title mentioning "cloud" is not evidence.
    """
    haystack = " ".join(
        str(values.get(field) or "") for field in ("org", "as_org", "isp", "server")
    )
    match = HOSTING_PROVIDER_PATTERN.search(haystack)
    return match.group(0).strip() if match else ""
