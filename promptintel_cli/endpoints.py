"""Declarative mapping of CLI commands to the supplied REST API reference."""

from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high", "critical")
COLLECTIONS = ("agent-files", "agent-threats", "prompts", "detection-rules")
INDICATOR_TYPES = (
    "url", "domain", "ip", "sha256", "file_path", "email", "package",
    "repository", "publisher", "skill", "mcp_server", "extension", "wallet", "messaging",
)


@dataclass(frozen=True)
class Query:
    name: str
    help: str
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    required: bool = False
    flag: str | None = None
    boolean: bool = False


@dataclass(frozen=True)
class Endpoint:
    command: str
    method: str
    path: str
    help: str
    service: str = "api"
    auth: bool = True
    queries: tuple[Query, ...] = ()
    body: bool = False
    consent: str | None = None
    native: str = "json"
    enterprise: bool = False


def q(name, help=None, **kwargs):
    return Query(name, help or name.replace("_", " "), **kwargs)


def limit(maximum, default):
    return q("limit", f"Items per page (server default: {default})", minimum=1, maximum=maximum)


severity = q("severity", choices=SEVERITIES)
page = q("page", minimum=1)
since = q("since", "ISO 8601 date or timestamp")
scan_kind = q("kind", choices=("skill", "mcp", "a2a", "ard"))
export_queries = (q("collection", choices=COLLECTIONS), since)
taxii_queries = (
    q("added_after", "Timestamp from X-TAXII-Date-Added-Last"), limit(2000, 500),
    q("next", "Opaque next-page cursor"),
    q("match[type]", "Comma-separated STIX types", flag="--match-type"),
    q("match[id]", "Comma-separated STIX object IDs", flag="--match-id"),
)

ENDPOINTS = (
    Endpoint("health", "GET", "/health", "API health (no key required)", auth=False),
    Endpoint("feed", "GET", "/agent-feed", "Curated agent protections", queries=(
        q("category"), severity, q("action"), since, q("technique_id"))),
    Endpoint("threat get", "GET", "/agent-threats/{id}", "One published agent threat"),
    Endpoint("threat export", "GET", "/agent-threats/{id}/iopc-export", "Pinned IoPC governance record", queries=(
        q("download", "Request downloadable JSON", boolean=True),)),
    Endpoint("check", "POST", "/check", "Check indicators; unknown does not mean clean", service="scanner"),
    Endpoint("keys", "GET", "/keys", "Public signing JWK set (no key required)", service="scanner", auth=False),
    Endpoint("quota", "GET", "/quota", "Scanner and indicator-check quota", service="scanner"),
    Endpoint("limits", "GET", "/agents/me/limits", "Account request and daily read limits"),
    Endpoint("rules manifest", "GET", "/rules", "NOVA pack manifest", service="scanner", enterprise=True,
             queries=(q("full", "Include rule text", boolean=True),)),
    Endpoint("rules download", "GET", "/rules.nov", "NOVA rule text (use --raw for a loadable file)",
             service="scanner", native="text", enterprise=True),
    Endpoint("rule-lab catalog", "GET", "/rule-lab/catalog", "Rule format and supported conditions", service="scanner"),
    Endpoint("rule-lab draft", "POST", "/rule-lab/draft", "Render and compile rule fields", service="scanner", body=True),
    Endpoint("rule-lab test", "POST", "/rule-lab/test", "Test a rule with attack and benign cases", service="scanner", body=True,
             consent="Send the rule and test texts to PromptIntel and its rule engine/model"),
    Endpoint("rule-lab card", "POST", "/rule-lab/card", "Rule readiness and last test", service="scanner", body=True),
    Endpoint("scan", "POST", "/scan", "Scan a remote source, card, or catalog", service="scanner"),
    Endpoint("scan-files", "POST", "/scan/files", "Upload explicitly selected local text files for scanning", service="scanner",
             consent="Send the selected files' contents to PromptIntel for scanning"),
    Endpoint("scans list", "GET", "/scans", "Search existing scans without using scan quota", service="scanner", queries=(
        q("q", "Name or source search"), scan_kind, q("verdict", choices=("clean", "suspicious", "malicious")), limit(25, 10))),
    Endpoint("scans get", "GET", "/scans/{content_hash}", "Stored scan by SHA-256", service="scanner"),
    Endpoint("duplicates check", "POST", "/duplicates/check", "Compare proposed metadata without storing it", body=True),
    Endpoint("reports submit", "POST", "/agents/reports", "Submit a threat report for review", body=True,
             consent="Submit this threat report to PromptIntel for review and possible publication"),
    Endpoint("reports list", "GET", "/agents/reports/mine", "Reports submitted using this API key"),
    Endpoint("reports edit", "PATCH", "/agents/reports/{id}", "Edit a pending report", body=True,
             consent="Send these changes to your pending PromptIntel report"),
    Endpoint("artifacts lookup", "GET", "/artifacts/lookup", "Check hashes, optionally hashing local files without uploading them"),
    Endpoint("artifacts list", "GET", "/artifacts", "Published malicious agent file entries", enterprise=True, queries=(
        q("q", "Title search"), q("kind"), severity, since, page, limit(100, 25))),
    Endpoint("artifacts get", "GET", "/artifacts/{id}", "Agent file entry and indicators", enterprise=True),
    Endpoint("detection-rules", "GET", "/detection-rules", "Published NOVA rules", enterprise=True, queries=(
        limit(200, 100), q("after", "Opaque pagination.next cursor"))),
    Endpoint("submissions submit", "POST", "/artifacts/submissions", "Submit malicious agent files for review", body=True,
             consent="Upload these agent files to PromptIntel for review and possible publication"),
    Endpoint("submissions list", "GET", "/artifacts/submissions/mine", "Your agent file submissions and review status", queries=(
        limit(100, 50), q("offset", minimum=0))),
    Endpoint("submissions edit", "PATCH", "/artifacts/submissions/{id}", "Edit a pending agent file submission", body=True,
             consent="Send these descriptive changes to your pending PromptIntel agent file submission"),
    Endpoint("prompts list", "GET", "/prompts", "Search and filter reviewed prompts", queries=(
        page, limit(50, 20), q("search"), q("entry", "IoPC technique or registry ID"), severity, q("category"))),
    Endpoint("prompts get", "GET", "/prompts/{id}", "One prompt, including untrusted attack text"),
    Endpoint("prompts indicators", "GET", "/prompts/indicators", "Typed indicators associated with prompts", enterprise=True, queries=(
        limit(500, 100), q("before", "Cursor timestamp (use with --before-id)"), q("before_id", "Cursor prompt ID (use with --before)"))),
    Endpoint("prompts submit", "POST", "/prompts/submit", "Submit an adversarial prompt for review", body=True,
             consent="Submit this adversarial prompt to PromptIntel for review and possible publication"),
    Endpoint("prompts search", "POST", "/prompts/search", "Search using a JSON query and filter body", body=True),
    Endpoint("taxonomy list", "GET", "/taxonomy", "Complete live IoPC taxonomy"),
    Endpoint("taxonomy entry", "GET", "/taxonomy/entries/{id}", "One IoPC entry and its framework mappings"),
    Endpoint("taxonomy mappings", "GET", "/taxonomy/mappings", "Live or version-pinned framework mappings", queries=(
        q("framework"), q("ref"), q("relationship", choices=(
            "equivalent", "related", "narrower_than", "broader_than", "control_relevant", "evidence_supports")),
        q("version", "Published taxonomy release", flag="--taxonomy-version"))),
    Endpoint("taxonomy translate", "GET", "/taxonomy/translate", "Translate an external framework item", queries=(
        q("framework", required=True), q("ref", required=True), q("to", "Target framework"))),
    Endpoint("taxonomy releases", "GET", "/taxonomy/releases", "Published taxonomy releases"),
    Endpoint("taxonomy release", "GET", "/taxonomy/releases/{version}", "Immutable taxonomy release snapshot"),
    Endpoint("taxonomy changelog", "GET", "/taxonomy/changelog", "Taxonomy audit trail", queries=(since, q("entry_id"), limit(200, 50))),
    Endpoint("taxii discovery", "GET", "/taxii2/", "TAXII 2.1 discovery", enterprise=True),
    Endpoint("taxii objects", "GET", "/taxii2/root/collections/{id}/objects/", "STIX objects of a TAXII collection",
             enterprise=True, queries=taxii_queries),
    Endpoint("taxii manifest", "GET", "/taxii2/root/collections/{id}/manifest/", "TAXII object IDs, dates, and versions",
             enterprise=True, queries=taxii_queries),
    Endpoint("export stix", "GET", "/export/stix.json", "STIX 2.1 bundle", enterprise=True, queries=export_queries),
    Endpoint("export indicators", "GET", "/export/indicators.csv", "Indicator CSV (use --raw to save CSV)", enterprise=True,
             native="csv", queries=(q("collection", choices=COLLECTIONS[:3]), since)),
)

BY_COMMAND = {endpoint.command: endpoint for endpoint in ENDPOINTS}
