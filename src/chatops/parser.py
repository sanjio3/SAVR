"""ChatOps query parsing (G11).

Extracts SCA query intent from free text or a URL: component name, version, and
advisory identifiers (CVE / GHSA / CNVD / CNNVD). Fully offline — URL parsing
reads only the URL string itself (path/query), it does NOT fetch the URL, so
tests need zero network access. Live fetching, if ever added, must be opt-in and
proxy-aware per 第四版 §2.15.
"""

import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}", re.IGNORECASE)
_CNVD_RE = re.compile(r"CNVD-\d{4}-\d{3,7}", re.IGNORECASE)
_CNNVD_RE = re.compile(r"CNNVD-\d{6}-\d{2,7}", re.IGNORECASE)

# component@version or component==version or "component version x.y.z"
_PKG_AT_RE = re.compile(r"([A-Za-z0-9_.\-/:]+)\s*(?:@|==|:)\s*(v?\d[\w.\-]*)")
_VERSION_RE = re.compile(r"\b(v?\d+\.\d+(?:\.\d+)?[\w.\-]*)\b")

# Known package-registry URL shapes -> (ecosystem, name[, version]).
_REGISTRY_HOSTS = {
    "pypi.org": "pypi",
    "npmjs.com": "npm",
    "www.npmjs.com": "npm",
    "mvnrepository.com": "maven",
    "pkg.go.dev": "go",
    "crates.io": "cargo",
    "rubygems.org": "rubygems",
}


def _advisory_ids(text: str) -> List[str]:
    ids: List[str] = []
    for pattern in (_CVE_RE, _GHSA_RE, _CNVD_RE, _CNNVD_RE):
        ids.extend(match.group(0).upper() for match in pattern.finditer(text or ""))
    # de-dupe, preserve order
    seen, unique = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            unique.append(i)
    return unique


def _parse_registry_url(parsed) -> Dict[str, Any]:
    host = parsed.netloc.lower()
    ecosystem = _REGISTRY_HOSTS.get(host, "")
    segments = [unquote(s) for s in parsed.path.split("/") if s]
    name = ""
    version = ""
    if host in ("pypi.org",) and segments:
        # /project/<name>/ or /project/<name>/<version>/
        if segments[0] in ("project", "simple") and len(segments) >= 2:
            name = segments[1]
            if len(segments) >= 3 and _VERSION_RE.fullmatch(segments[2]):
                version = segments[2]
    elif "npmjs.com" in host and segments:
        # /package/<name> or /package/<name>/v/<version>
        if segments[0] == "package" and len(segments) >= 2:
            name = segments[1]
            if len(segments) >= 4 and segments[2] == "v":
                version = segments[3]
    elif host == "mvnrepository.com" and segments:
        # /artifact/<group>/<artifact>/<version>
        if segments[0] == "artifact" and len(segments) >= 3:
            name = f"{segments[1]}:{segments[2]}"
            if len(segments) >= 4:
                version = segments[3]
    elif host == "pkg.go.dev" and segments:
        name = "/".join(segments)
        if "@" in name:
            name, version = name.split("@", 1)
    elif host == "crates.io" and segments:
        if segments[0] == "crates" and len(segments) >= 2:
            name = segments[1]
            if len(segments) >= 3:
                version = segments[2]
    elif host == "rubygems.org" and segments:
        if segments[0] == "gems" and len(segments) >= 2:
            name = segments[1]
    return {"ecosystem": ecosystem, "name": name, "version": version}


def parse_query(text: str) -> Dict[str, Any]:
    """Parse a ChatOps query (text or URL) into a structured intent dict."""
    text = (text or "").strip()
    result: Dict[str, Any] = {
        "raw": text,
        "is_url": False,
        "ecosystem": "",
        "name": "",
        "version": "",
        "advisory_ids": [],
    }
    if not text:
        return result

    parsed = urlparse(text)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        result["is_url"] = True
        reg = _parse_registry_url(parsed)
        result.update({k: v for k, v in reg.items() if v})
        # advisory ids may live in the path or query string
        haystack = f"{unquote(parsed.path)} {unquote(parsed.query)}"
        result["advisory_ids"] = _advisory_ids(haystack)
        # query params may carry name/version explicitly
        qs = parse_qs(parsed.query)
        for key in ("package", "name", "q"):
            if not result["name"] and qs.get(key):
                result["name"] = qs[key][0]
        if not result["version"] and qs.get("version"):
            result["version"] = qs["version"][0]
        return result

    # Free text
    result["advisory_ids"] = _advisory_ids(text)
    at_match = _PKG_AT_RE.search(text)
    if at_match:
        result["name"] = at_match.group(1)
        result["version"] = at_match.group(2)
    else:
        version_match = _VERSION_RE.search(text)
        if version_match:
            result["version"] = version_match.group(1)
        # heuristic: first token that isn't a version / advisory id / keyword
        keywords = {"是否", "使用", "漏洞", "版本", "check", "does", "use", "vuln", "在", "用了", "有没有"}
        for token in re.split(r"[\s,，、]+", text):
            token = token.strip()
            if not token or token == result["version"]:
                continue
            if token.upper() in result["advisory_ids"] or token in keywords:
                continue
            if _VERSION_RE.fullmatch(token):
                continue
            if re.match(r"^[A-Za-z0-9_.\-/:]+$", token):
                result["name"] = token
                break
    return result
