"""Command-line interface for every documented PromptIntel REST endpoint."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from urllib.parse import quote, urlsplit

from . import __version__
from .client import Client, ClientError, Redactor, verify_sha256
from .credentials import manage_credentials, validate_profile
from .diagnostics import doctor
from .endpoints import ENDPOINTS, INDICATOR_TYPES
from .indicators import parse_input, validate_indicators
from .output import render
from .pagination import PAGINATED, fetch_pages
from .policy import POLICY_COMMANDS, evaluate, parse_fail_on

MAX_BODY_BYTES = 20 * 1024 * 1024
MAX_SCAN_BYTES = 3 * 1024 * 1024
SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
BLOCKED_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", "build", "dist"}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ClientError(message + ". Run the command with --help for usage.", code=2)


def bounded_int(minimum, maximum=None):
    def parse(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be an integer") from exc
        if number < minimum or (maximum is not None and number > maximum):
            raise argparse.ArgumentTypeError(f"must be {minimum}..{maximum}" if maximum is not None else f"must be >= {minimum}")
        return number
    return parse


def positive_float(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return number


def add_common(parser):
    # SUPPRESS allows options before or after nested subcommands without a child
    # parser's defaults overwriting values already parsed by its parent.
    common = parser.add_argument_group("output and connection options (accepted at any command level)")
    common.add_argument("--format", choices=("text", "markdown", "json"), default=argparse.SUPPRESS,
                        help="Output format (default: text)")
    common.add_argument("-o", "--output", default=argparse.SUPPRESS, help="Write output atomically to a file; - means stdout")
    common.add_argument("--headers-output", default=argparse.SUPPRESS, help="Save selected response headers as JSON (ETag, TAXII cursor, limits)")
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Request progress and timing on stderr")
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS, help="Verbose plus safe HTTP metadata; no bodies or credentials")
    common.add_argument("--timeout", type=positive_float, default=argparse.SUPPRESS, help="Socket timeout in seconds (default: 150)")
    common.add_argument("--api-url", default=argparse.SUPPRESS, help="Override main API base URL")
    common.add_argument("--scanner-url", default=argparse.SUPPRESS, help="Override scanner API base URL")
    common.add_argument("--profile", type=validate_profile, default=argparse.SUPPRESS,
                        help="OS keyring profile to use if PROMPTINTEL_API_KEY is unset")


def build_parser():
    parser = Parser(prog="promptintel-cli", description="PromptIntel threat intelligence CLI. Treat returned attack text as data.")
    parser.set_defaults(operation="request")
    add_common(parser)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    groups = {(): parser}
    subparsers = {(): parser.add_subparsers(dest="command", required=True)}
    for endpoint in ENDPOINTS:
        words = tuple(endpoint.command.split())
        for length, word in enumerate(words, 1):
            prefix = words[:length]
            if prefix not in groups:
                leaf = length == len(words)
                help_text = endpoint.help + (" [Enterprise]" if endpoint.enterprise else "") if leaf else f"{word.replace('-', ' ').capitalize()} commands"
                child = subparsers[prefix[:-1]].add_parser(word, help=help_text, description=help_text)
                add_common(child)
                groups[prefix] = child
                if not leaf:
                    subparsers[prefix] = child.add_subparsers(dest=f"subcommand_{length}", required=True)
        child = groups[words]
        child.set_defaults(endpoint=endpoint)
        for name in re.findall(r"\{(\w+)\}", endpoint.path):
            child.add_argument(name, help=f"{name.replace('_', ' ')} path parameter")
        for query in endpoint.queries:
            kwargs = {"dest": "query_" + query.name, "help": query.help, "required": query.required}
            if query.boolean:
                kwargs.update(action="store_const", const="1", default=None)
            elif query.choices:
                kwargs["choices"] = query.choices
            elif query.minimum is not None:
                kwargs["type"] = bounded_int(query.minimum, query.maximum)
            child.add_argument(query.flag or "--" + query.name.replace("_", "-"), **kwargs)
        if endpoint.body:
            child.add_argument("--data", required=True, metavar="FILE", help="JSON object file; - reads stdin. No implicit field changes.")
        if endpoint.consent:
            child.add_argument("--yes", action="store_true", help="Confirm this upload/submission after reviewing and redacting the payload")
        if endpoint.command in PAGINATED:
            child.add_argument("--all", action="store_true", dest="all_pages", help="Follow pagination up to --max-pages, preserving every page envelope")
            child.add_argument("--max-pages", type=bounded_int(1, 100), help="Maximum requests with --all (default: 5; maximum: 100)")
        if endpoint.command in POLICY_COMMANDS:
            child.add_argument("--fail-on", metavar="VERDICTS", help="Comma-separated verdicts that return policy exit code 6; add unknown/incomplete explicitly")
        if endpoint.command == "check":
            child.add_argument("values", nargs="*", help="Indicator values (never prompt text or secrets)")
            child.add_argument("--type", choices=INDICATOR_TYPES, help="Explicit type for positional and untyped input values")
            child.add_argument("--indicator", action="append", default=[], metavar="TYPE=VALUE", help="Add a typed indicator; repeat to mix types")
            child.add_argument("--method", choices=("post", "get"), default="post", help="GET supports one typed value or several untyped values")
            child.add_argument("--input", action="append", default=[], metavar="FILE", help="Add indicators from a UTF-8 file; - reads stdin (repeatable)")
            child.add_argument("--input-format", choices=("auto", "text", "json"), default="auto", help="One indicator per line, or a JSON array/indicators object (default: auto)")
        elif endpoint.command == "artifacts lookup":
            child.add_argument("hashes", nargs="*", help="SHA-256 digests, separate or comma-separated")
            child.add_argument("--file", action="append", default=[], help="Hash this local file; only the hash is sent (repeatable)")
        elif endpoint.command == "scan":
            child.add_argument("source", nargs="?", help="Repository, URL, install command, domain, or inline card JSON")
            child.add_argument("--source-file", metavar="FILE", help="Read a card/config as source text; - reads stdin (requires consent)")
            child.add_argument("--yes", action="store_true", help="Confirm sending the contents of --source-file")
            child.add_argument("--kind", choices=("auto", "skill", "mcp", "a2a", "ard"), default="auto")
            child.add_argument("--static", action="store_true", help="Skip deep review; static signal is not a verdict")
            child.add_argument("--private", action="store_true", help="Keep the result out of the public scan feed")
            child.add_argument("--fresh", action="store_true", help="Ignore cached scan results")
            child.add_argument("--server-key-env", metavar="NAME", help="Environment variable containing the target MCP server credential")
            child.add_argument("--key-header", help="First authentication header to try for the target MCP server")
        elif endpoint.command == "scan-files":
            child.add_argument("files", nargs="+", help="Explicit relative UTF-8 file paths under --root; no recursion or symlinks")
            child.add_argument("--root", default=".", help="Root directory for relative file paths (default: current directory)")
            child.add_argument("--kind", required=True, choices=("skill", "mcp"))
            child.add_argument("--name", help="Skill/server label (default: root folder name)")
            child.add_argument("--static", action="store_true")
            child.add_argument("--public", action="store_true", help="List this scan publicly (local scans default to private)")
        elif endpoint.command == "rules manifest":
            child.add_argument("--etag", help="Previously saved ETag, sent in If-None-Match")
        elif endpoint.command == "rules download":
            child.add_argument("--sha256", help="Expected SHA-256 from the manifest; also verifies the header checksum if present")
        if endpoint.native != "json":
            child.add_argument("--raw", action="store_true", help="Write original native bytes instead of formatted output (untrusted content)")
    inventory = subparsers[()].add_parser("endpoints", help="List all supported REST endpoint mappings")
    add_common(inventory)
    inventory.set_defaults(endpoint=None, operation="endpoints")
    diagnostics = subparsers[()].add_parser("doctor", help="Check API connectivity, authentication, account plan, and scanner quotas")
    add_common(diagnostics)
    diagnostics.set_defaults(endpoint=None, operation="doctor")
    auth = subparsers[()].add_parser("auth", help="Save, inspect or delete an OS keyring profile (requires the keyring extra)")
    add_common(auth)
    actions = auth.add_subparsers(dest="auth_action", required=True)
    for action, description in (("set", "Save/replace a key using hidden terminal input"),
                                ("status", "Check whether the named profile is stored; never display the key"),
                                ("delete", "Delete the named profile from the OS credential store")):
        child = actions.add_parser(action, help=description, description=description + ". Profile defaults to default.")
        add_common(child)
        child.set_defaults(endpoint=None, operation="auth")
    return parser


def read_text_file(filename, limit=MAX_BODY_BYTES):
    try:
        if filename == "-":
            raw = sys.stdin.buffer.read(limit + 1) if hasattr(sys.stdin, "buffer") else sys.stdin.read(limit + 1).encode("utf-8")
        else:
            with Path(filename).open("rb") as handle:
                raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise ClientError(f"Input exceeds {limit} bytes", code=2)
        return raw.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ClientError(f"Cannot read UTF-8 input: {exc}", code=2) from exc


def load_body(filename):
    def reject_constant(value):
        raise ValueError("Non-finite JSON number")
    try:
        body = json.loads(read_text_file(filename), parse_constant=reject_constant)
    except ValueError as exc:
        raise ClientError("--data must contain a valid JSON object", code=2) from exc
    if not isinstance(body, dict):
        raise ClientError("--data must contain a JSON object, not an array or scalar", code=2)
    return body


def confirm(message, args, *, stdin_used=False):
    if getattr(args, "yes", False):
        return
    if stdin_used or not sys.stdin.isatty():
        raise ClientError(message + ". Review and redact the payload, then pass --yes to confirm.", code=5)
    print(message + "? [y/N] ", end="", file=sys.stderr, flush=True)
    if sys.stdin.readline().strip().lower() not in ("y", "yes"):
        raise ClientError("Cancelled; nothing was sent", code=5)


def file_hash(filename):
    try:
        digest = hashlib.sha256()
        with Path(filename).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise ClientError(f"Cannot hash file: {exc}", code=2) from exc


def scan_files_body(args):
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise ClientError("--root must be a directory", code=2)
    if not 1 <= len(args.files) <= 300:
        raise ClientError("Select between 1 and 300 files", code=2)
    files, seen, total = [], set(), 0
    for filename in args.files:
        relative = PurePosixPath(filename)
        if relative.is_absolute() or ".." in relative.parts or "\\" in filename or not relative.parts:
            raise ClientError("Scan file paths must be relative, with no '..' or backslashes", code=2)
        if any(part in BLOCKED_PARTS for part in relative.parts):
            raise ClientError("Exclude dependencies, .git, virtual environments, and build output from scans", code=2)
        candidate = root
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ClientError("Symlinks are not accepted for local scans", code=2)
        if not candidate.is_file() or not candidate.resolve().is_relative_to(root):
            raise ClientError("Each selected scan path must be a regular file inside --root", code=2)
        path = relative.as_posix()
        if path in seen:
            raise ClientError("The local scan file list contains a duplicate path", code=2)
        seen.add(path)
        # Scan files preserve their exact UTF-8 text, including any BOM.
        try:
            with candidate.open("rb") as handle:
                raw = handle.read(MAX_SCAN_BYTES - total + 1)
            total += len(raw)
            if total > MAX_SCAN_BYTES:
                raise ClientError("Local scan content exceeds 3 MiB", code=2)
            content = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ClientError("Scan files must be readable UTF-8 text", code=2) from exc
        if "\x00" in content:
            raise ClientError("Binary files (NUL bytes) cannot be scanned", code=2)
        files.append({"path": path, "content": content})
    return {"kind": args.kind, "name": args.name or root.name, "files": files,
            "deep_review": not args.static, "private": not args.public}


def prepare_request(args, client):
    endpoint = args.endpoint
    method, path = endpoint.method, endpoint.path
    params = [(query.name, getattr(args, "query_" + query.name)) for query in endpoint.queries
              if getattr(args, "query_" + query.name) is not None]
    for name in re.findall(r"\{(\w+)\}", path):
        value = getattr(args, name)
        if not value or value in (".", "..") or any(ord(char) < 32 for char in value):
            raise ClientError("Invalid path parameter", code=2)
        if name == "content_hash" and not SHA256.fullmatch(value):
            raise ClientError("content_hash must be a 64-character SHA-256", code=2)
        path = path.replace("{" + name + "}", quote(value, safe=""))
    body = load_body(args.data) if endpoint.body else None
    if endpoint.command == "check":
        indicators = list(args.values)
        for item in args.indicator:
            type_name, separator, value = item.partition("=")
            if not separator or type_name not in INDICATOR_TYPES or not value.strip():
                raise ClientError("--indicator requires a supported TYPE=VALUE", code=2)
            indicators.append({"type": type_name, "value": value})
        if args.input.count("-") > 1:
            raise ClientError("Standard input can only be read once", code=2)
        for filename in args.input:
            indicators.extend(parse_input(read_text_file(filename), args.input_format))
        indicators = validate_indicators(indicators, args.type, client.redactor)
        if args.method == "get":
            method = "GET"
            if any(isinstance(item, dict) for item in indicators) and len(indicators) != 1:
                raise ClientError("GET /check permits a type only with a single value; use POST for mixed types", code=2)
            params = [("value", item["value"] if isinstance(item, dict) else item) for item in indicators]
            if isinstance(indicators[0], dict):
                params.append(("type", indicators[0]["type"]))
        else:
            body = {"indicators": indicators}
    elif endpoint.command == "artifacts lookup":
        hashes = [part.strip().lower() for value in args.hashes for part in value.split(",")]
        hashes.extend(file_hash(filename) for filename in args.file)
        hashes = list(dict.fromkeys(hashes))
        if not 1 <= len(hashes) <= 50 or any(not SHA256.fullmatch(value) for value in hashes):
            raise ClientError("Provide 1 to 50 valid SHA-256 hashes, directly or using --file", code=2)
        params = [("sha256", value) for value in hashes]
    elif endpoint.command == "scan":
        if bool(args.source) == bool(args.source_file):
            raise ClientError("Provide exactly one source argument or --source-file", code=2)
        source = read_text_file(args.source_file) if args.source_file else args.source
        if not source.strip() or len(source) > 8000:
            raise ClientError("Scan source must contain 1 to 8,000 characters", code=2)
        body = {"source": source, "kind": args.kind, "deep_review": not args.static,
                "private": args.private, "fresh": args.fresh}
        if args.key_header and not args.server_key_env:
            raise ClientError("--key-header requires --server-key-env", code=2)
        if args.server_key_env:
            secret = os.environ.get(args.server_key_env)
            if not secret:
                raise ClientError("The target server credential environment variable is empty or missing", code=2)
            client.redactor.add(secret)
            # The service accepts target credentials only for HTTPS MCP endpoints.
            target = urlsplit(source)
            if target.scheme != "https" or not target.hostname or target.username or target.password:
                raise ClientError("A target MCP server credential requires an HTTPS endpoint URL without embedded credentials", code=2)
            body["key"] = secret
            body["private"] = True
            if args.key_header:
                body["key_header"] = args.key_header
        if args.source_file:
            confirm("Send the source file's contents to PromptIntel for scanning", args, stdin_used=args.source_file == "-")
    elif endpoint.command == "scan-files":
        body = scan_files_body(args)
    elif endpoint.command == "prompts indicators":
        if bool(getattr(args, "query_before")) != bool(getattr(args, "query_before_id")):
            raise ClientError("--before and --before-id must be supplied together", code=2)
    if endpoint.consent:
        confirm(endpoint.consent, args, stdin_used=getattr(args, "data", None) == "-")
    return method, path, params, body


def validate_destination(filename):
    if not filename or filename == "-":
        return
    path = Path(filename)
    if not path.parent.is_dir() or path.is_dir():
        raise ClientError("Output destination must be a file in an existing directory", code=2)


def write_output(filename, content):
    if not filename or filename == "-":
        if isinstance(content, bytes):
            if hasattr(sys.stdout, "buffer"):
                sys.stdout.buffer.write(content)
            else:
                sys.stdout.write(content.decode("utf-8"))
        else:
            sys.stdout.write(content)
        return
    path = Path(filename)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".promptintel-cli-", delete=False) as handle:
            temporary = handle.name
            handle.write(content if isinstance(content, bytes) else content.encode("utf-8"))
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def selected_headers(response):
    names = {"etag", "last-modified", "content-type", "retry-after", "x-ratelimit-reason",
             "x-taxii-date-added-first", "x-taxii-date-added-last", "x-promptintel-pack-sha256"}
    headers = response if isinstance(response, dict) else response.headers
    return {key: value for key, value in headers.items() if key in names or key.startswith("x-ratelimit-")}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    output_format = "text"
    # Keep parse-time errors machine-readable too, including invalid arguments.
    for index, arg in enumerate(argv):
        candidate = arg.split("=", 1)[1] if arg.startswith("--format=") else argv[index + 1] if arg == "--format" and index + 1 < len(argv) else None
        if candidate in ("text", "markdown", "json"):
            output_format = candidate
    redactor = Redactor(os.environ.get("PROMPTINTEL_API_KEY", ""))
    try:
        args = build_parser().parse_args(argv)
        output_format = getattr(args, "format", "text")
        output = getattr(args, "output", None)
        headers_output = getattr(args, "headers_output", None)
        validate_destination(output)
        validate_destination(headers_output)
        if headers_output == "-":
            raise ClientError("--headers-output must name a file; stdout is reserved for the response", code=2)
        if headers_output and output and output != "-" and Path(headers_output).resolve() == Path(output).resolve():
            raise ClientError("Response and header output paths must be different", code=2)
        if args.operation == "endpoints":
            rows = [{"command": endpoint.command, "method": endpoint.method, "path": endpoint.path,
                     "service": endpoint.service, "access": "enterprise" if endpoint.enterprise else "api_key" if endpoint.auth else "public"}
                    for endpoint in ENDPOINTS]
            rows.append({"command": "check --method get", "method": "GET", "path": "/check", "service": "scanner", "access": "api_key"})
            write_output(output, render({"endpoints": rows}, output_format))
            return 0
        if args.operation == "auth":
            if headers_output:
                raise ClientError("auth commands do not make HTTP requests; --headers-output does not apply", code=2)
            payload, code = manage_credentials(args.auth_action, getattr(args, "profile", "default"), redactor)
            write_output(output, render(redactor.value(payload), output_format, title="PromptIntel credentials"))
            return code
        client = Client(api_url=getattr(args, "api_url", None), scanner_url=getattr(args, "scanner_url", None),
                        timeout=getattr(args, "timeout", 150), verbose=getattr(args, "verbose", False), debug=getattr(args, "debug", False),
                        profile=getattr(args, "profile", None))
        redactor = client.redactor
        if args.operation == "doctor":
            payload, code, headers = doctor(client)
            if headers_output:
                write_output(headers_output, render(redactor.value({name: selected_headers(value) for name, value in headers.items()}), "json"))
            write_output(output, render(payload, output_format, title="PromptIntel CLI diagnostics"))
            return code
        if args.endpoint.auth:
            client.require_credentials()
            if client.profile and client.credential_source == "environment":
                client.log("Using PROMPTINTEL_API_KEY; the selected keyring profile is overridden")
        all_pages = getattr(args, "all_pages", False)
        if getattr(args, "max_pages", None) is not None and not all_pages:
            raise ClientError("--max-pages requires --all", code=2)
        fail_on = parse_fail_on(args.fail_on, args.endpoint.command) if getattr(args, "fail_on", None) is not None else None
        method, path, params, body = prepare_request(args, client)
        if all_pages:
            response, page_headers = fetch_pages(client, args.endpoint, path, params, args.max_pages or 5)
            headers = {"pages": [selected_headers(value) for value in page_headers]}
        else:
            response = client.request(method, path, service=args.endpoint.service, params=params, body=body,
                                      auth=args.endpoint.auth, native=args.endpoint.native, etag=getattr(args, "etag", None), label=args.endpoint.command)
            headers = selected_headers(response)
        expected_results = None
        if args.endpoint.command == "check":
            expected_results = len(body["indicators"]) if body is not None else sum(key == "value" for key, _ in params)
        exit_code = evaluate(response.payload, args.endpoint.command, fail_on, expected_results=expected_results)
        if args.endpoint.command == "rules download":
            checked = verify_sha256(response, getattr(args, "sha256", None))
            client.log("Rule pack SHA-256 verified" if checked else "No checksum supplied or advertised; compare with the manifest before loading")
        if getattr(args, "raw", False):
            decoded = response.raw.decode("utf-8")
            if redactor.text(decoded) != decoded:
                raise ClientError("Native output contains a credential and cannot be written unchanged; use formatted output for redaction")
            content = response.raw
        else:
            content = render(response.payload, output_format, native=response.native)
        if headers_output:
            write_output(headers_output, render(redactor.value(headers), "json"))
        write_output(output, content)
        if output and output != "-":
            client.log("Response saved successfully")
        if exit_code:
            client.log("Response matched the configured --fail-on policy")
        return exit_code
    except ClientError as exc:
        print(render(redactor.value(exc.payload), output_format, title="PromptIntel error"), end="", file=sys.stderr)
        return exc.code
    except (OSError, ValueError, RecursionError) as exc:
        payload = {"error": "local_error", "message": redactor.text(str(exc))}
        print(render(payload, output_format, title="PromptIntel error"), end="", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(render({"error": "interrupted", "message": "Interrupted"}, output_format), end="", file=sys.stderr)
        return 130
