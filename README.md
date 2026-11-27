# promptintel-cli

Repository: [forensicdave/promptintel-cli](https://github.com/forensicdave/promptintel-cli).

**Independent project:** This repository is my independent work - it is not an official PromptIntel project and is not authorized, endorsed, or sponsored by PromptIntel.

Free and open-source under the [MIT licence](LICENSE). See the [changelog](CHANGELOG.md) for release changes. The licence covers this client; PromptIntel API access and data remain subject to the service's terms.

A Python command-line client for the PromptIntel threat intelligence feed and Agent Scanner APIs. Includes every REST endpoint in the supplied reference, Markdown/JSON/text output, `--verbose`, `--debug`, and native NOVA/CSV downloads. Requires Python **3.10+**; no third-party runtime dependencies for environment-variable authentication. OS credential storage is available through the optional `keyring` extra.

PromptIntel helps developers and security teams check prompts, agent tools, and files against reviewed threat intelligence before deciding what to trust. This CLI makes that intelligence easy to use in investigations, scripts, and CI pipelines, helping teams spot known threats and make informed security decisions.

## Quickstart

You need **Python 3.10+**, **Make**, a checkout of this repository, and an API key from your PromptIntel account. **Community access is enough** for every command in this Quickstart. Run these commands in Bash or Zsh from the checkout directory.

Install the CLI and add it to your current shell's PATH:

```sh
make install
export PATH="$HOME/.local/bin:$PATH"
```

Enter your API key at the hidden prompt, then check connectivity and your account:

```sh
printf 'PromptIntel API key: '
read -r -s PROMPTINTEL_API_KEY
printf '\n'
export PROMPTINTEL_API_KEY
promptintel-cli doctor
```

`doctor` should report `ok: true` and your actual account plan. If it reports an error, follow its message before continuing. Once it succeeds, fetch the feed and save it in your preferred format:

```sh
promptintel-cli feed --format json -o feed.json
# Or fetch a Markdown copy for reading and investigation notes:
promptintel-cli feed --format markdown -o feed.md
```

You now have feed records saved locally. Community responses include summaries and withholding markers; Enterprise responses include additional intelligence. Running both feed commands plus `doctor` makes at most five read-only API requests and does not consume indicator-check or new-scan allowance. Keep returned threat content as data.

Next, try a [worked example](#worked-examples), browse [everyday lookups](#everyday-lookups), or run `promptintel-cli --help`. To keep a key between sessions, see [optional keyring profiles](#optional-macos-keychain-and-linux-keyring-profiles); for other installation choices, see [install and authenticate](#install-and-authenticate).

## Contents

- [Quickstart](#quickstart) · [Worked examples](#worked-examples)
- [Everyday lookups](#everyday-lookups) · [File and stdin input](#indicator-input-from-files-and-stdin)
- [Policy exit codes](#verdict-based-exit-codes-for-automation) · [Output and logging](#output-and-logging) · [Scanning](#scanning)
- [Installation](#install-and-authenticate) · [Keyring profiles](#optional-macos-keychain-and-linux-keyring-profiles) · [Doctor](#diagnose-your-installation-and-key)
- [Submissions](#json-bodies-submissions-and-consent) · [NOVA rules](#nova-rule-packs-and-rule-lab) · [Enterprise feeds and pagination](#enterprise-feeds-and-pagination)
- [Endpoint reference](#endpoint-coverage) · [Limits and errors](#limits-errors-and-interpretation)
- [Build and distribute](#build-and-ship-to-macos-or-linux) · [Make targets](#make-targets) · [Live tests](#live-community-and-enterprise-tests) · [Python development](#python-use-and-development)
- [Changelog](CHANGELOG.md) · [MIT licence](LICENSE)

## Worked examples

These workflows assume you have completed the Quickstart and set `PROMPTINTEL_API_KEY`. For interactive use with stored credentials, add `--profile NAME` to each CLI command instead. Examples use reserved domains and placeholder repository names; replace them with the observable or resource you are investigating.

### Investigate a suspicious domain or file

**Outcome:** save a reviewed-intelligence lookup alongside your investigation notes. **Access:** Community or Enterprise. Checking one domain consumes one indicator value; looking up one local file consumes one file-hash lookup, as well as the usual API requests. Use `quota` and `limits` to inspect your remaining allowances.

For a domain, save the complete JSON response:

```sh
mkdir -p investigation
promptintel-cli check example.com --format json -o investigation/domain-check.json
```

For a file, replace `./SKILL.md` with its actual local path. This hashes the file locally and sends only its SHA-256:

```sh
mkdir -p investigation
promptintel-cli artifacts lookup --file ./SKILL.md \
  --format markdown -o investigation/file-lookup.md
```

The following **illustrative excerpts** show a fictional reviewed match at each access level. Other response fields are omitted.

Community indicator-check excerpt:

```json
{
  "data": {
    "detail": "summary",
    "results": [{"value": "sample.example", "verdict": "known"}]
  }
}
```

Enterprise indicator-check excerpt:

```json
{
  "data": {
    "detail": "full",
    "results": [{"value": "sample.example", "verdict": "block"}]
  }
}
```

| Result | How to use it |
| --- | --- |
| Community `known` | The value appears in reviewed records; treat it as untrusted. The summary does not expose the full verdict or supporting matches. |
| Enterprise `block`, `require_approval`, `warn` or `log` | Read the supporting matches and apply your own policy; the CLI does not enforce the action. |
| Either plan's `unknown` | No reviewed match was found. It is not a clean result. |

A file-hash match identifies that exact file, while an unknown hash leaves its safety unresolved. Review the saved response and any `source.complete`, `source.stale` or withholding markers before recording a conclusion. If further scanning is needed, use the [scanning workflow](#scanning), which explains when file contents are uploaded and how to confirm that upload.

### Review a skill before installing it

**Outcome:** obtain and read a scan report before deciding whether to install a skill. **Access:** Community or Enterprise. Searching or reading an existing scan does not consume new-scan allowance; a new scan can consume one. Check `quota` before requesting one.

Replace the placeholder repository URL, then look for an existing scan:

```sh
skill_source='https://github.com/owner/repo'
promptintel-cli scans list --q "$skill_source" --kind skill --format json
```

If a result matches the resource and version you intend to use, copy its `content_hash` into this command and read the saved report:

```sh
promptintel-cli scans get CONTENT_SHA256 --format markdown -o skill-review.md
```

If no suitable report is available, request a private scan with deep review:

```sh
promptintel-cli scan "$skill_source" --kind skill --private \
  --format json -o skill-scan.json
```

Read `data.verdict`, `data.deep_review_completed` and the report. Investigate `suspicious` or `malicious` findings before proceeding. A null verdict means deep review did not produce a verdict; a static signal alone does not establish trust. A completed `clean` result is evidence to consider with the tool's permissions and your installation policy. The CLI does not install or execute the skill. A response with `cached: true` reused an existing scan and did not spend new-scan allowance.

### Use indicator checks in a CI pipeline

**Outcome:** stop a pipeline on selected threat verdicts, incomplete intelligence or an operational failure, while retaining the result for review. **Access:** Community or Enterprise, subject to indicator allowance. Each run consumes one check per input value; a request above the remaining allowance is refused. Use a small, deliberate list on Community rather than running this on every commit without considering quota.

Install the CLI in the job and inject `PROMPTINTEL_API_KEY` through your CI platform's secret store. Provide `indicators.txt` with one value per line, for example:

```text
example.com
example.net
```

Run this as a POSIX shell step in a fresh job workspace:

```sh
#!/bin/sh
set -eu
: "${PROMPTINTEL_API_KEY:?Configure PROMPTINTEL_API_KEY as a CI secret}"
mkdir -p reports

check_status=0
promptintel-cli check --input indicators.txt \
  --fail-on known,block,require_approval,warn,incomplete \
  --format json -o reports/indicator-check.json || check_status=$?

case "$check_status" in
  0) printf '%s\n' 'No configured policy matched; the pipeline may continue.' ;;
  6) printf '%s\n' 'Policy matched; stop and review the saved result.' >&2
     exit 6 ;;
  *) printf 'Indicator check failed (exit %s); stop the pipeline.\n' "$check_status" >&2
     exit "$check_status" ;;
esac
```

This policy stops on Community `known`, Enterprise `block`/`require_approval`/`warn`, and explicit incompleteness markers. It permits `unknown` and `log` to continue; `unknown` still means absence of reviewed intelligence, not proof of safety. Add `unknown` to `--fail-on` if it should require review too. On Community, selecting both `known` and `unknown` will stop every completed check by design.

Configure the pipeline so later steps require this step to succeed. Exit `6` is a policy match; other nonzero exits indicate errors such as authentication failure or rate limiting. Do not convert those failures into success or retry a 429 immediately. Retain `reports/indicator-check.json` as an internal job artifact for exits `0` and `6`. Failed requests do not write a new result, so use a fresh workspace to avoid mistaking an earlier file for the current response. See [policy exit codes](#verdict-based-exit-codes-for-automation) for the full choices and [limits and errors](#limits-errors-and-interpretation) for operational exits.

## Everyday lookups

```sh
# Fetch the curated protections, optionally since your previous poll.
promptintel-cli feed --format markdown -o protections.md
promptintel-cli feed --severity critical --since 2026-11-01T00:00:00Z --format json
promptintel-cli feed --category mcp --action block --technique-id IOPC-T3.002
promptintel-cli threat get THREAT_ID
promptintel-cli threat export THREAT_ID --format json -o governance.json

# Check values, not prompt text. POST is the default.
promptintel-cli check example.com https://example.com/path
promptintel-cli check --indicator package=lodash.merge --indicator skill=get-weather-data
promptintel-cli check ms-python.python --type extension --format json
promptintel-cli check example.com --method get

# Hash locally; only the SHA-256 is sent, never the file contents.
promptintel-cli artifacts lookup --file ./SKILL.md --file ./server.json --format json
promptintel-cli artifacts lookup YOUR_64_CHARACTER_SHA256

# Search prompts. Community list/search results withhold attack text.
promptintel-cli prompts list --search 'credential theft' --severity high --page 1 --limit 20
promptintel-cli prompts list --entry IOPC-T1.002 --format markdown
promptintel-cli prompts get PROMPT_ID --format json
promptintel-cli prompts search --data examples/prompt-search.json --format json

# Taxonomy and framework translation.
promptintel-cli taxonomy entry IOPC-T1.001
promptintel-cli taxonomy translate --framework OWASP_LLM --ref LLM01 --to MITRE_ATLAS
promptintel-cli taxonomy mappings --framework OWASP_LLM --taxonomy-version 2.2.0
promptintel-cli taxonomy releases
promptintel-cli taxonomy release 2.2.0 --format json
promptintel-cli taxonomy changelog --since 2026-11-01 --limit 50
```

`check` accepts 1–100 values. Use explicit types for dotted package/extension names, which otherwise look like domains. Repeat `--indicator TYPE=VALUE` to mix types. `--type` applies to positional values and untyped strings from input files. GET allows several untyped values or one typed value. Never send prompt text or secrets to `/check`; prompt text matching belongs in a local rule engine.

Hash lookup accepts 1–50 distinct SHA-256 values, as separate arguments, comma-separated arguments, and/or repeatable `--file` options. It handles binary files without uploading them.

## Indicator input from files and stdin

```sh
# One indicator per line; blank lines are ignored.
promptintel-cli check --input indicators.txt --format json
printf '%s\n' example.com example.net | promptintel-cli check --input -

# JSON supports mixed explicit types.
promptintel-cli check --input examples/indicators.json --format json
promptintel-cli check --input packages.txt --type package

# Combine inputs into one request (100 indicators maximum in total).
promptintel-cli check example.com --input extra-indicators.json --input - < more.txt
```

`--input` is repeatable; `-` reads stdin once. Files must be UTF-8. Auto-detection treats input beginning with `[` or `{` as JSON and everything else as one value per line. Override it with `--input-format text` or `--input-format json` (applies to all input files). Text mode trims surrounding whitespace and ignores blank lines; it has no comment syntax.

JSON accepts an array or an object containing only an `indicators` array:

```json
{
  "indicators": [
    "example.com",
    {"type": "package", "value": "lodash.merge"},
    {"type": "extension", "value": "ms-python.python"}
  ]
}
```

Each item must be a string or an object containing only `type` and `value`. Explicit types override `--type`. Empty/malformed input, control characters, recognizable API credentials, and totals above 100 fail before sending a request. Inputs are not deduplicated or automatically batched: every value sent consumes indicator allowance, including repeats. Community allowances may be smaller than the request maximum; check `quota` first.

## Verdict-based exit codes for automation

By default, a successful HTTP/API request exits `0`, whatever the verdict. Add `--fail-on` to return **`6` when any result matches your chosen policy**. Normal output is still printed or saved on exit `6`.

```sh
# Enterprise verdicts, plus Community's known/unknown responses.
promptintel-cli check --input indicators.txt \
  --fail-on block,require_approval,known,unknown,incomplete --format json -o checks.json

# Apply a policy to an existing scan without requesting a new scan.
promptintel-cli scans get CONTENT_SHA256 --fail-on malicious,suspicious,unknown,incomplete

# The same option works on scan and scan-files; upload consent still applies.
promptintel-cli scan https://github.com/owner/repo --private \
  --fail-on malicious,suspicious,unknown,incomplete
```

| Commands | Accepted comma-separated values |
| --- | --- |
| `check` | `block`, `require_approval`, `warn`, `log`, `known`, `unknown`, `incomplete` |
| `scan`, `scan-files`, `scans get` | `clean`, `suspicious`, `malicious`, `unknown`, `incomplete` |

Values match exactly; choosing `warn` does not implicitly include `block`. Community checks return `known`/`unknown`, so include `known` when treating a reviewed match as a policy failure. Include `unknown` if absence of intelligence should fail your policy—it does not mean clean.

`incomplete` matches indicator responses marked incomplete or stale, or with partial/unavailable prompt-indicator or agent-file sources. For scans, a null verdict matches both `unknown` and `incomplete`; `deep_review_completed: false` also matches `incomplete`. Static signals are never substituted for a verdict. Missing or malformed verdict data, including missing indicator results, returns error `1` when a policy is enabled. Authentication, rate-limit, and other request errors keep their existing exit codes.

For shell scripts, handle policy matches separately from operational failures:

```sh
check_status=0
promptintel-cli check example.com --fail-on known,block,require_approval,unknown,incomplete \
  --format json -o check.json || check_status=$?
case "$check_status" in
  0) printf '%s\n' 'No configured policy matched; review the result.' ;;
  6) printf '%s\n' 'Policy matched; review check.json before proceeding.' ;;
  *) printf 'Lookup failed (exit %s).\n' "$check_status" >&2; exit "$check_status" ;;
esac
```

For a complete CI step that stops later work on policy matches and request failures, see [use indicator checks in a CI pipeline](#use-indicator-checks-in-a-ci-pipeline).

## Output and logging

Common options can appear before the command, after it, or after a nested subcommand:

```sh
promptintel-cli --verbose --format json feed > feed.json
promptintel-cli feed --format markdown -o feed.md
promptintel-cli feed --format text
promptintel-cli --debug taxonomy entry IOPC-T1.001 --format json 2> debug.log
```

| Option | Behavior |
| --- | --- |
| `--format text` | Default: readable, indented fields and numbered list entries. |
| `--format markdown` | Markdown heading and a fenced text block containing all response fields. Attack strings cannot close the fence or render active HTML. |
| `--format json` | Pretty-printed JSON preserving the API envelope, pagination, access flags, warnings, and metadata. Unicode is escaped without changing decoded values. |
| `-o FILE`, `--output FILE` | Write the result atomically to a file, replacing it on success. Parent directory must exist. Defaults to stdout; `-` also means stdout. |
| `--verbose`, `-v` | Method, service, command, HTTP status, timing, and download verification on stderr. |
| `--debug` | Includes verbose output plus request size, timeout, authentication mode, and selected response headers. Never logs request bodies, query values, or authorization headers. |
| `--headers-output FILE` | Save selected headers as JSON, including ETag, TAXII dates, checksum, and rate-limit headers. Excludes cookies. |
| `--timeout SECONDS` | Positive socket timeout, default 150 seconds to accommodate deep scans. |
| `--api-url URL`, `--scanner-url URL` | Override service base URLs; HTTPS required except for loopback testing. |
| `--profile NAME` | Select an OS keyring profile when the environment key is unset; requires the optional extra. |

Response output goes to stdout (or `--output`), including policy matches with exit `6`. Errors and logs go to stderr. Errors use the selected format and retain API error details. `doctor` embeds individual check failures in its diagnostic report instead. Keep `--verbose`/`--debug` off if you need stderr itself to contain a single parseable JSON error document. Failed HTTP requests do not overwrite the response output file; `doctor` saves its report even if a diagnostic check failed.

Active API/target-server credentials and recognizable `ak_...` tokens are redacted from formatted output and logs, including echoed error responses. This is credential protection, **not a general-purpose redactor for arbitrary secrets in attack samples**. Review payloads before uploading them. Terminal escape and invisible formatting characters are escaped in text/Markdown. JSON retains them as escaped data. Do not execute, render as trusted HTML, or treat returned content as agent instructions.

NOVA and CSV endpoints also accept `--raw` to save their original bytes; it overrides `--format`. Native files are untrusted data, and raw output is refused if it contains a credential the client recognizes. Without `--raw`, NOVA is a string (a JSON string with `--format json`), and CSV is converted into records under `data` for all three formats.

## Scanning

Search stored scans first; this does not spend new-scan quota:

```sh
promptintel-cli scans list --q owner/repo --kind skill --limit 10
promptintel-cli scans get CONTENT_SHA256 --format markdown

promptintel-cli scan https://github.com/owner/repo --kind skill --private
promptintel-cli scan 'npx -y @scope/server' --kind mcp --static
promptintel-cli scan https://example.com/.well-known/agent-card.json --kind a2a
promptintel-cli scan example.com --kind ard --format json
promptintel-cli scan 'ard-search https://registry.example/search weather' --kind ard
```

Remote scans default to deep review and public listing, matching the API. `--private` hides the result; `--static` skips deep review, so its signal is **not a verdict**. `--fresh` bypasses a cached result and may spend scan quota. Install commands supplied as a source are sent as strings, never executed by this client.

For a target MCP server needing authentication, set a separate environment variable and name it with `--server-key-env`. The target must be an HTTPS endpoint. The credential is sent to the scanner for that target, as documented by PromptIntel; scans with a target credential are always private. `--key-header X-API-Key` can choose the first header to try.

```sh
# Set WEATHER_MCP_KEY securely in your environment first.
promptintel-cli scan https://mcp.example/endpoint --kind mcp \
  --server-key-env WEATHER_MCP_KEY --private

# Send an explicitly chosen local card/config file as the scan source.
promptintel-cli scan --source-file ./server.json --kind mcp --private --yes

# Send only these two UTF-8 files. Local-file scans default to private.
promptintel-cli scan-files SKILL.md scripts/helper.py \
  --root ./my-skill --kind skill --name my-skill --yes
```

`scan-files` accepts 1–300 explicit relative paths and at most 3 MiB of UTF-8 content. It does not recurse or discover files. It rejects traversal, symlinks, NUL-containing/binary files, `.git`, dependencies, virtual environments, and build output. Files keep their relative paths. Inspect selected files for secrets before consenting. Use `--public` only if you want a local scan listed publicly.

## Install and authenticate

For a portable installation from this checkout:

```sh
make install
export PATH="$HOME/.local/bin:$PATH"
promptintel-cli --help
```

This installs a single file at `~/.local/bin/promptintel-cli`, using the `python3` on your PATH. Add the PATH line to `~/.zshrc` or `~/.bashrc` if needed. To develop the client inside a virtual environment instead:

```sh
make setup
. .venv/bin/activate
promptintel-cli --help
```

`make install` and `make build` require only Python 3.10+ and Make; they work offline. `make setup` installs the editable Python package using pip and setuptools. You can also run directly from this directory without installing anything:

```sh
python3 -m promptintel_cli --help
python3 -m promptintel_cli health --format json
```

By default, authenticated commands read **`PROMPTINTEL_API_KEY`** from the environment. There is no raw-key command-line option or CLI-managed plaintext credential file. Alternatively, select a stored OS keyring profile as described below. The supplied test key is deliberately absent from the source, examples, and tests. To enter your key without displaying it or putting its literal value in shell history, run this in Bash or Zsh:

```sh
printf 'PromptIntel API key: '
read -r -s PROMPTINTEL_API_KEY
printf '\n'
export PROMPTINTEL_API_KEY

promptintel-cli limits --format json
promptintel-cli quota
promptintel-cli doctor
promptintel-cli feed --severity high
```

`health` and `keys` need no API key and do not send one, even if it is set. `endpoints` is entirely local.

## Optional macOS Keychain and Linux keyring profiles

Install the optional dependency in the same Python environment that runs the CLI. From this checkout:

```sh
make setup-keyring
. .venv/bin/activate

# Each set command prompts for a key with terminal echo disabled.
promptintel-cli auth set --profile community
promptintel-cli auth set --profile enterprise

# An environment key takes precedence; unset it to use the selected profile.
unset PROMPTINTEL_API_KEY
promptintel-cli --profile community doctor
promptintel-cli --profile enterprise feed --format json
promptintel-cli auth status --profile enterprise
```

`make setup-keyring` runs `pip install -e '.[keyring]'` inside `.venv`. For a pipx installation from this checkout, use `pipx install '.[keyring]'`. After publishing to a package index, the extra is named `promptintel-cli[keyring]`. Installing the base package continues to require no third-party runtime dependencies.

| Command | Behavior |
| --- | --- |
| `auth set --profile NAME` | Prompt for a key, save or replace it in the OS store, and verify the saved value. Requires a terminal; refuses echoing fallback or piped input. |
| `auth status --profile NAME` | Report the backend, profile presence and whether an environment key overrides it. Returns `3` if absent. Does not validate the key with PromptIntel. |
| `auth delete --profile NAME` | Remove that stored profile and verify deletion. Does not revoke the API key or change the environment. |
| `--profile NAME` on an API command | Use this stored key only when `PROMPTINTEL_API_KEY` is unset or empty. |

Auth commands default to the profile `default`. API commands require explicit selection (`--profile default` to use it); they do not silently search for stored keys. Profiles are case-sensitive labels of 1–64 letters, digits, dots, underscores or hyphens, starting with a letter/digit. They are not secrets or guarantees of account tier: `doctor` reports the actual plan returned by the API. Keys are stored under service name `promptintel-cli` and username equal to the profile name.

Credential precedence is: **nonempty environment key → explicitly selected keyring profile → missing-key error**. Auth management commands always operate on their named stored profile, even if an environment key is set. Their output shows `environment_override`; `doctor` shows `credential_source`, `requested_profile`, the active `credential_profile`, and `credential_backend`. Public commands (`health`, `keys`), help and endpoint inventory never access the keyring. Backend error details are replaced with fixed messages so echoed credentials cannot enter logs or reports. No command prints a stored key.

The supported native backends are macOS Keychain, Linux Secret Service/libsecret and KWallet. File-based, null and unknown backends are refused. If keyring selects a chain of stores, the client chooses its first supported native store and uses only that store; missing or locked credentials do not trigger fallback to another backend. Keep backend selection consistent when saving and reading profiles.

Linux needs a working credential service and session; installing the Python extra alone does not provide them. Secret Service needs D-Bus and an unlocked collection; KWallet may need separately installed D-Bus bindings. Headless servers and CI can continue using environment credentials. See the [keyring documentation](https://keyring.readthedocs.io/en/stable/) for platform setup and access-control details. On macOS, other programs using the same Python executable may have access to these items under its Keychain permissions.

The portable executable does **not** bundle `keyring` or its dependencies. `make install` still installs only that file. To use it with the extra installed in `.venv`, run it with that interpreter:

```sh
make build
.venv/bin/python ./dist/promptintel-cli --profile enterprise doctor
```

The selected interpreter must have the extra installed. Missing dependencies return exit `2`; an unavailable/locked/unsupported store or missing stored key returns `3`. No plaintext fallback is created.

## Diagnose your installation and key

```sh
promptintel-cli doctor
promptintel-cli doctor --format json -o diagnostics.json
promptintel-cli doctor --debug --timeout 20
```

`doctor` reports the client/Python versions, operating system, credential source and selected profile, whether a key could be loaded, API connectivity, account plan and allowances, and scanner quota. It makes at most three read-only requests: public `health`, authenticated `limits`, and scanner `quota`. It does not run scans, check indicators, or submit content. Both Community and Enterprise keys are supported.

The diagnostic report goes to stdout or `--output`, including when a check fails. It never includes the key. Exit `0` means all checks succeeded; missing/invalid credentials, credential-store failures or denied access return `3`, missing optional keyring dependencies return `2`, rate limits return `4`, and other diagnostic failures return `1`. With no key or selected profile, it still checks public health and marks authenticated checks skipped: set `PROMPTINTEL_API_KEY` or select `--profile NAME` to enable them. A keyring failure is reported after public health; it is not retried for the second authenticated check. A rate limit stops the remaining checks without retrying; other failures allow independent checks to finish. `--headers-output` groups selected headers by check name.

## JSON bodies, submissions, and consent

Commands with structured bodies take `--data FILE`, or `--data -` for UTF-8 JSON on stdin. The body must be an object. Fields are forwarded unchanged; validation of the full submission schema is performed by the API. This preserves explicit `null` edits and fields added by the service. The client does not invent report fingerprints, add fields to submissions, or encode prompt text automatically.

Reports, prompt/file submissions, edits, local uploads, and Rule Lab tests ask for confirmation on an interactive terminal. In scripts, after reviewing and redacting the payload, pass **`--yes`**. Without confirmation, nothing is sent. Stdin payloads always require `--yes` for these commands, so JSON input cannot accidentally answer the prompt. Read-only checks, searches, and duplicate lookups do not prompt.

```sh
# Compare proposed metadata before reporting; nothing is stored by this lookup.
promptintel-cli duplicates check --data examples/duplicate-check.json

# Template only: edit it to contain real, redacted evidence before submitting.
# Generate a UUID v4 once for a new report; retain it when retrying that report.
python3 -c 'import uuid; print(uuid.uuid4())'
promptintel-cli reports submit --data report.json --yes --format json
promptintel-cli reports list
promptintel-cli reports edit REPORT_ID --data report-update.json --yes

promptintel-cli submissions list --limit 50 --offset 0
promptintel-cli submissions submit --data agent-files.json --yes
promptintel-cli submissions edit SUBMISSION_ID --data file-update.json --yes
promptintel-cli prompts submit --data prompt-submission.json --yes
```

Start a report from [`examples/report-template.json`](examples/report-template.json), replace its placeholders and fingerprint, and save it as `report.json`. Its fingerprint is an example, not a reusable identifier for unrelated reports. Use `adds_to` for new evidence about a published record. File submissions need their own fingerprint and file objects (`path` with `content` or `content_base64`). The client preserves the supplied fingerprint on every attempt; it does not retry automatically. Edits send only changed fields; reports cannot change `fingerprint`, and file-submission edits cannot change files or hashes.

Prompt submissions should use UTF-8 base64 in `prompt_base64` (and optionally `nova_rule_base64`) to avoid the API firewall rejecting attack text in clear. Base64 is encoding, not redaction. For example, encode a reviewed, redacted local sample without sending it anywhere:

```sh
python3 -c 'import base64, pathlib; print(base64.b64encode(pathlib.Path("sample.txt").read_bytes()).decode())'
```

Set `is_public: false` in a prompt submission to request Enterprise-only visibility. The CLI does not submit sample fixtures during its tests.

## NOVA rule packs and Rule Lab

Enterprise rule pack downloads:

```sh
promptintel-cli rules manifest --full --format json \
  -o manifest.json --headers-output manifest-headers.json

# Copy the exact ETag, including its quotes, from the saved headers.
promptintel-cli rules manifest --etag '"YOUR_ETAG"' --format json

# Copy sha256 from the manifest. Native bytes are verified before writing.
promptintel-cli rules download --raw --sha256 EXPECTED_SHA256 -o promptintel.nov
promptintel-cli detection-rules --limit 100 --format json
```

The manifest supports `If-None-Match`: HTTP 304 produces `{"not_modified": true, "etag": "..."}` and exit 0. It does not contain a new manifest: keep your prior manifest separately instead of overwriting it with this result. For downloads, the client verifies both `--sha256`, when provided, and `X-PromptIntel-Pack-Sha256`, when returned. A mismatch prevents writing the file. If neither checksum is available, compare against the manifest yourself before loading the rules. No rule engine is bundled, and downloaded rules are never executed. JWS attestations are returned unchanged; **signature verification is not implemented**. `promptintel-cli keys --format json` fetches the public verification keys for a separate verifier.

Rule Lab uses the scanner API on every plan:

```sh
promptintel-cli rule-lab catalog --format json -o rule-catalog.json
promptintel-cli rule-lab draft --data examples/rule-draft.json --format json -o draft-result.json

# Build rule-test.json with the exact returned rule_text and your test cases.
promptintel-cli rule-lab test --data rule-test.json --yes --format json -o test-result.json

# rule-card.json contains {"rule_text": "the exact drafted and tested text"}.
promptintel-cli rule-lab card --data rule-card.json --format json
```

Review the catalog before drafting. [`examples/rule-draft.json`](examples/rule-draft.json) is a harmless two-keyword format demonstration, not a production detector. Tests send case texts to PromptIntel's engine and possibly its model. Follow the API's readiness findings; a ready result is evidence about the supplied tests, not a safety guarantee.

## Enterprise feeds and pagination

```sh
promptintel-cli artifacts list --severity high --page 1 --limit 25
promptintel-cli artifacts get ARTIFACT_ID --format json
promptintel-cli prompts indicators --limit 100 --format json

promptintel-cli taxii discovery --format json
promptintel-cli taxii objects agent-files --limit 500 \
  --added-after 2026-11-01T00:00:00Z --match-type indicator,report \
  --format json -o objects.json --headers-output taxii-headers.json
promptintel-cli taxii manifest agent-threats --format json

promptintel-cli export stix --collection agent-files --format json -o bundle.json
promptintel-cli export indicators --collection agent-threats --since 2026-11-01 \
  --raw -o indicators.csv
```

List commands perform **one request by default**. You can continue manually, keeping the same filters:

| Endpoint family | Continue with |
| --- | --- |
| `prompts list`, `artifacts list` | Increment `--page`; use the response's pagination information. |
| `submissions list` | Increment `--offset` by the returned row count. |
| `detection-rules` | Pass `pagination.next` unchanged as `--after`. |
| `prompts indicators` | Pass both fields of `next` as `--before` and `--before-id`. |
| `taxii objects`, `taxii manifest` | While `more` is true, pass the returned `next` cursor as `--next`; retain the same filters. |

All seven commands in this table also support bounded automatic pagination:

```sh
promptintel-cli prompts list --severity high --limit 20 --all --max-pages 3 \
  --format json -o prompt-pages.json
promptintel-cli detection-rules --all --format json -o rule-pages.json
promptintel-cli taxii objects agent-files --all --max-pages 4 \
  --format json -o object-pages.json --headers-output taxii-page-headers.json
```

`--all` follows pages until the end or a cap of **five requests by default**. `--max-pages` requires `--all` and accepts **1–100**. `--limit` still sets the size of each page; the current page/offset/cursor is the starting point. Filters remain unchanged. Each page consumes the usual API allowance.

With `--all`, the response has this wrapper in every output format:

```json
{
  "pages": ["each original API response envelope is retained here"],
  "pagination": {
    "pages_fetched": 3,
    "max_pages": 3,
    "complete": false,
    "stop_reason": "max_pages",
    "next_query": {"severity": "high", "limit": 20, "page": 4}
  }
}
```

`pages` contains the actual response objects, including access restrictions, warnings and cursors. Reaching the cap is a successful bounded fetch (exit `0`), **not evidence of a complete collection**: check `pagination.complete`. At the end, it is `true`, `stop_reason` is `end`, and `next_query` is null. Resume a capped fetch using the fields in `next_query`, for example `--severity high --limit 20 --page 4 --all`. With `--all`, the headers file contains a `pages` array in the same order.

Numbered/offset pagination uses server metadata when available, otherwise a short or empty page signals completion. A full final page without metadata may require one extra empty request. Cursor endpoints require continuation metadata for nonempty pages. Repeated cursors and malformed metadata fail with exit `1`; a failed page stops the operation without retries or writing a partial response/header file. Errors include the count of previously accepted pages and the failed query. Combined response bodies are capped at 64 MiB.

For a later TAXII polling cycle, use the saved `x-taxii-date-added-last` header as `--added-after` after completing the current collection. For `--all`, take it from the last page; when capped, continue with `next_query` first. TAXII uses Bearer authentication and the TAXII 2.1 Accept header. CSV native downloads retain the API's spreadsheet-formula escaping.

## Endpoint coverage

`promptintel-cli endpoints --format json` lists all command/method/path/service mappings. Each leaf command has `--help` with its filters. The CLI uses the main API at `https://api.promptintel.securitybreak.io/api/v1` and the scanner API at `https://promptintel.securitybreak.io/scanner-api/v1`.

`doctor` is a composite diagnostic command using `health`, `limits` and `quota`, so it is not a separate endpoint in that inventory. `auth set`, `auth status` and `auth delete` operate only on the local OS credential store and make no API requests.

| Command | Method / path | Service |
| --- | --- | --- |
| `health` | GET `/health` | Main, public |
| `feed` | GET `/agent-feed` | Main |
| `threat get ID` | GET `/agent-threats/{id}` | Main |
| `threat export ID` | GET `/agent-threats/{id}/iopc-export` | Main |
| `check` | POST or GET `/check` | Scanner |
| `keys` | GET `/keys` | Scanner, public |
| `quota` | GET `/quota` | Scanner |
| `limits` | GET `/agents/me/limits` | Main |
| `rules manifest`, `rules download` | GET `/rules`, `/rules.nov` | Scanner, Enterprise |
| `rule-lab catalog` | GET `/rule-lab/catalog` | Scanner |
| `rule-lab draft`, `test`, `card` | POST `/rule-lab/draft`, `/rule-lab/test`, `/rule-lab/card` | Scanner |
| `scan`, `scan-files` | POST `/scan`, `/scan/files` | Scanner |
| `scans list`, `scans get HASH` | GET `/scans`, `/scans/{content_hash}` | Scanner |
| `duplicates check` | POST `/duplicates/check` | Main |
| `reports submit` | POST `/agents/reports` | Main |
| `reports list` | GET `/agents/reports/mine` | Main |
| `reports edit ID` | PATCH `/agents/reports/{id}` | Main |
| `artifacts lookup` | GET `/artifacts/lookup` | Main |
| `artifacts list`, `artifacts get ID` | GET `/artifacts`, `/artifacts/{id}` | Main, Enterprise |
| `detection-rules` | GET `/detection-rules` | Main, Enterprise |
| `submissions submit` | POST `/artifacts/submissions` | Main |
| `submissions list` | GET `/artifacts/submissions/mine` | Main |
| `submissions edit ID` | PATCH `/artifacts/submissions/{id}` | Main |
| `prompts list`, `prompts get ID` | GET `/prompts`, `/prompts/{id}` | Main |
| `prompts indicators` | GET `/prompts/indicators` | Main, Enterprise |
| `prompts submit`, `prompts search` | POST `/prompts/submit`, `/prompts/search` | Main |
| `taxonomy list` | GET `/taxonomy` | Main |
| `taxonomy entry ID` | GET `/taxonomy/entries/{id}` | Main |
| `taxonomy mappings`, `translate`, `releases`, `changelog` | GET matching `/taxonomy/...` path | Main |
| `taxonomy release VERSION` | GET `/taxonomy/releases/{version}` | Main |
| `taxii discovery` | GET `/taxii2/` | Main, Enterprise |
| `taxii objects ID`, `taxii manifest ID` | GET `/taxii2/root/collections/{id}/objects/`, `/manifest/` | Main, Enterprise |
| `export stix`, `export indicators` | GET `/export/stix.json`, `/export/indicators.csv` | Main, Enterprise |

This is a REST client. It does not implement the separate MCP protocol or its tool doors. Environment overrides `PROMPTINTEL_API_URL` and `PROMPTINTEL_SCANNER_URL` are also supported; command-line overrides take priority. Only point overrides at a service you trust with the API credential. Standard Python HTTP proxy environment settings apply; TLS certificate verification stays enabled.

## Limits, errors, and interpretation

- A successful lookup with `unknown` is not a clean bill of health. Community `known`/summary answers and withheld fields are preserved; the client does not fill in missing intelligence.
- Decisions, matches, and recommendations are data for your policy. The CLI does not block addresses, install anything, enforce feed protections, or interpret attack text as instructions. Respect revocation and `expires_at` when consuming a feed.
- Enterprise-only commands may return `403 enterprise_required` for Community keys. Use `limits` and `quota` to inspect the account's actual allowances rather than assuming the documented defaults are still current.
- Requests are not retried, including POST/PATCH and HTTP 429. A 429 error includes `Retry-After` and `X-RateLimit-Reason` when supplied, plus guidance to wait. It does not sleep and retry in a loop.
- Redirects are not followed, so credentials and submissions cannot be forwarded to another address. A merged record's 301 response exposes `merged_into` and `location`; request the retained ID explicitly.
- HTML instead of expected data produces an actionable error. The two API base URLs are different from website pages.
- Responses are capped at 64 MiB, JSON input files at 20 MiB. The API applies its own endpoint-specific limits in addition to client-side argument/file limits.

| Exit code | Meaning |
| --- | --- |
| `0` | Request succeeded, including 304; not a safety verdict. |
| `1` | API/server, network, response, checksum, or local output error. |
| `2` | Invalid CLI argument, input file/body, or configuration. |
| `3` | Missing credentials, invalid stored credentials, credential-store failure, HTTP 401, or HTTP 403 (including Enterprise access). |
| `4` | HTTP 429; wait before retrying. |
| `5` | Required upload/submission consent absent or declined. |
| `6` | A verdict or completeness condition matched the explicit `--fail-on` policy; response output is retained. |
| `130` | Interrupted. |

## Build and ship to macOS or Linux

The simplest release is **`dist/promptintel-cli`**, a single executable Python zip archive. It bundles the client source and needs **Python 3.10+ on the destination**. It works with macOS/Linux and Intel/ARM Python installations because it contains no platform-specific binaries. It does not bundle Python itself. The [Python zipapp documentation](https://docs.python.org/3/library/zipapp.html) describes this executable archive format.

```sh
make check
make build
./dist/promptintel-cli --version
./dist/promptintel-cli endpoints --format json
```

Copy `dist/promptintel-cli` to the other machine by your usual file-transfer method. For example, after placing it in Downloads on the destination:

```sh
mkdir -p "$HOME/.local/bin"
install -m 755 "$HOME/Downloads/promptintel-cli" "$HOME/.local/bin/promptintel-cli"
export PATH="$HOME/.local/bin:$PATH"
promptintel-cli --version
```

Then set `PROMPTINTEL_API_KEY` securely on that machine using the instructions above. No key or environment file is bundled. The artifact includes package `.py` files, its launcher, and the MIT `LICENSE`, not the workspace, virtual environment, examples, tests, or build caches. Rebuilding unchanged sources in the same build environment produces identical artifact bytes.

You can also run the file without installing it or changing its executable bit:

```sh
python3 ./promptintel-cli --help
# If your default python3 is too old, choose an installed supported interpreter:
python3.12 ./promptintel-cli feed --format json
```

The builder works without Make as well: `python3 scripts/build_zipapp.py`. `make build` also creates `dist/SHA256SUMS` so you can check transferred files. From a directory containing the release artifacts and checksum manifest:

```sh
# macOS
shasum -a 256 -c SHA256SUMS
# Linux
sha256sum -c SHA256SUMS
```

For conventional Python distribution, `make dist` builds all of:

- `dist/promptintel-cli`: the portable executable.
- `dist/promptintel_cli-VERSION-py3-none-any.whl`: an installable Python wheel.
- `dist/promptintel_cli-VERSION.tar.gz`: a source distribution with the Makefile, build scripts, examples, and tests.
- `dist/SHA256SUMS`: checksums for the artifacts.

`make dist` creates `.venv` if necessary, installs setuptools 77+ there, and calls its standard wheel/source build hooks. This may need PyPI access; the portable `make build` path does not. All three distributions include the MIT licence; the source archive also includes `CHANGELOG.md`. Change `__version__` in `promptintel_cli/__init__.py` for a new release; package metadata, CLI version, and HTTP User-Agent all read that one value. Use `make clean` before building a release to remove older artifacts.

Distribute the wheel through your release downloads or Python package index. With pipx already installed, install a downloaded wheel as an isolated command-line tool:

```sh
pipx install ./promptintel_cli-0.1.0-py3-none-any.whl
pipx ensurepath
promptintel-cli --help
```

Pipx keeps CLI packages in separate environments and exposes their commands on PATH; see the [Python packaging guide](https://packaging.python.org/en/latest/guides/installing-stand-alone-command-line-tools/). For an offline wheel install without pipx:

```sh
python3 -m venv "$HOME/.local/share/promptintel-cli-venv"
"$HOME/.local/share/promptintel-cli-venv/bin/python" -m pip install --no-index --no-deps \
  ./promptintel_cli-0.1.0-py3-none-any.whl
"$HOME/.local/share/promptintel-cli-venv/bin/promptintel-cli" --help
```

Building makes local artifacts only; it does not publish or upload a release.

## Make targets

Run `make` or `make help` to see the available targets. The Makefile works with macOS's bundled GNU Make 3.81 and newer GNU Make on Linux; recipes use `/bin/sh`.

| Target | Purpose |
| --- | --- |
| `make venv` | Create `.venv`. |
| `make setup` | Install the project in editable mode inside `.venv`. |
| `make setup-keyring` | Install the editable project and optional OS keyring dependency in `.venv`. |
| `make run ARGS='feed --format json'` | Run the source with the selected Python interpreter. Default arguments: `--help`. |
| `make test` | Run offline CLI and distribution tests; no key required. |
| `make test-live` | Run the opt-in Community/Enterprise API checks and save a sanitized JSON report. |
| `make check` | Run tests and compile-check the Python sources. |
| `make build`, `make zipapp`, `make all` | Build the portable executable and checksums without network access. |
| `make build-tools` | Install setuptools into `.venv` for package builds. |
| `make dist` | Build portable, wheel, and source artifacts with checksums. |
| `make install` | Build and install the portable file to `~/.local/bin/promptintel-cli`. |
| `make uninstall` | Remove the portable installation. |
| `make clean` | Remove `build/`, `dist/`, package build metadata, and project bytecode caches; keep `.venv`. |
| `make distclean` | Also remove `.venv`. |

Common overrides:

```sh
make build PYTHON=python3.12
make install PREFIX="$HOME/tools"          # installs tools/bin/promptintel-cli
make uninstall PREFIX="$HOME/tools"
make install PREFIX=/usr/local DESTDIR=/tmp/promptintel-cli-stage  # staged packaging
make setup PIP_FLAGS=--no-build-isolation  # if setuptools is already available
```

`PYTHON` selects the source/build/test interpreter and the interpreter used to create a new `.venv`; it does not replace an existing virtual environment or change the portable launcher's `python3` shebang. `PREFIX` defaults to `$HOME/.local`; use the same `PREFIX`/`DESTDIR` for uninstall. `ARGS` is interpreted by the shell, so quote values as you would in a terminal and do not insert untrusted strings into it. `make install` does not require sudo at its default destination. On Linux distributions that package `venv` separately, install that component before using `make setup` or `make dist`.

## Live Community and Enterprise tests

`make test` stays offline and never reads your real keys. Use **`make test-live`** explicitly to exercise the actual CLI against both PromptIntel services with a Community key and an Enterprise key.

Use either stored OS keyring profiles or a private JSON key file. For profiles saved with the commands above:

```sh
make test-live LIVE_AUTH=keyring PYTHON=.venv/bin/python

# Optional custom profile names; the default names are community and enterprise.
make test-live LIVE_AUTH=keyring PYTHON=.venv/bin/python \
  LIVE_COMMUNITY_PROFILE=testing-community LIVE_ENTERPRISE_PROFILE=testing-enterprise

# Equivalent direct invocation:
.venv/bin/python scripts/test_live.py --keyring
```

Keyring mode reads both profiles directly, ignores any inherited `PROMPTINTEL_API_KEY`, and does not read or create a plaintext key file. It checks the actual plans through the existing live matrix. `LIVE_AUTH` defaults to `file` for compatibility.

For file mode, create `~/.config/promptintel-cli/test-keys.json` outside the checkout, using this structure with your own keys:

```json
{
  "community": "YOUR_COMMUNITY_KEY",
  "enterprise": "YOUR_ENTERPRISE_KEY"
}
```

Both values must be real `ak_...` credentials. Keep the file private, then run:

```sh
chmod 600 ~/.config/promptintel-cli/test-keys.json
make test-live
```

The runner reads the selected credential source and passes only the relevant key to each CLI subprocess through `PROMPTINTEL_API_KEY`. Keys never appear in process arguments. Public checks run without a key. It pins requests to the documented PromptIntel API hosts, ignoring base-URL environment overrides, and captures debug/verbose output in memory to verify HTTP statuses and look for credential leaks. Keyring mode checks retrieval once before running the matrix; it does not re-open the keyring for every subprocess.

| Test | Community | Enterprise |
| --- | --- | --- |
| `health`, `keys` | Public checks run once, without either key | Same public checks |
| `limits`, `quota` | Account must report Community; quota request succeeds | Account must report Enterprise; quota request succeeds |
| `feed` | Summary access and withheld indicators | Full access without withheld indicators |
| `prompts list --limit 1` | Attack text/rules withheld | Attack text available |
| `check example.com` | Summary result, known/unknown | Detailed verdict format |
| `artifacts list`, `detection-rules` | HTTP 403 identifying an Enterprise requirement, CLI exit 3 | Successful listings |
| `rules manifest`, `rules download` | Expected Enterprise access denial | Manifest plus native download matching its SHA-256 |
| `taxii discovery` | Expected Enterprise access denial | Discovery returns API roots |

This is a small access-level smoke suite, not exhaustive validation of every endpoint or of threat detection accuracy. `example.com` is checked as a single domain indicator; the test does not assume it is known or clean. No rule engine runs, no files are uploaded, no reports are submitted, and no new scans or Rule Lab tests are created. The only POST is the read-only indicator check.

At most **22 HTTP requests** are made: two public requests and ten per key, including **one indicator value per key**. Requests start at least four seconds apart by default, so a full run normally takes about 90 seconds plus API latency. Requests are never retried. A 429, network failure, or server outage stops the remaining requests. A wrong account plan or failed authentication stops checks for that key. Plans belong to accounts: two keys from the same upgraded account may both have Enterprise access.

The sanitized JSON report is saved to **`.test-results/live.json`**, which is ignored by Git and excluded from source distributions. It contains test names, expected plan labels, outcomes, CLI exit codes, HTTP statuses, fixed explanations, and a summary. Access-denial diagnostics record whether stdout was empty, which standard error fields were present, their structure, and whether an Enterprise requirement was recognized. They never copy error messages or arbitrary error codes. The report contains no credentials, raw API bodies, raw debug logs, indicators, or attack text. Native rule bytes are checked in memory and discarded. Report files are created with owner-only permissions. Empty lists or missing evidence of the required visibility are marked `inconclusive`, rather than silently counted as passes.

Community denials can express the Enterprise requirement through a top-level or nested `error`/`code`, a message, or TAXII's `title`, `description`, or `error_code`. The runner accepts these formats while still requiring HTTP 403, CLI exit 3, empty stdout, and no traceback. An unrelated or unexplained 403 remains a failure; it is not assumed to be an Enterprise restriction.

Overrides:

```sh
make test-live LIVE_KEYS=/private/path/test-keys.json
make test-live LIVE_REPORT=/tmp/promptintel-cli-live.json
make test-live LIVE_INTERVAL=6 LIVE_TIMEOUT=30

# Recheck only the three Community denial formats (four requests including limits).
# This does not consume any indicator-check allowance, and keeps the full report.
make test-live LIVE_PLAN=community \
  LIVE_CASES=rules_manifest,rules_download,taxii_discovery \
  LIVE_REPORT=.test-results/community-denials.json

# The runner is also usable directly from a source checkout:
python3 scripts/test_live.py --help
```

`LIVE_PLAN` selects `both` (default), `community`, or `enterprise`. `LIVE_CASES` selects `all` (default) or comma-separated names: `health`, `public_keys`, `limits`, `quota`, `feed`, `prompts`, `indicator_check`, `artifacts`, `detection_rules`, `rules_manifest`, `rules_download`, `taxii_discovery`. Filtered runs still verify `limits` before testing a key, and add the rule manifest before an Enterprise rule download. Unselected checks are omitted, rather than counted as skipped; a successful focused run certifies only the selected checks and their prerequisites. Both distinct keys remain required in the chosen credential source, even for filtered runs. The direct runner's `--keyring` and `--keys-file` options are mutually exclusive; `--community-profile`/`--enterprise-profile` require `--keyring`.

`LIVE_INTERVAL` and `LIVE_TIMEOUT` are positive seconds. The default socket timeout is 20 seconds, with a subprocess timeout five seconds longer. The direct Python runner returns `0` only when every selected check passes, `1` for a failed expectation, `2` for invalid configuration/report access, `3` for blocked or inconclusive coverage, and `130` for interruption. Make reports any nonzero runner result as a failed target. Expected Community denials are passes; unexpected denials are failures.

If this environment cannot reach the API hosts, run `make test-live` in your own terminal and share `.test-results/live.json` for review. Do not share the key file. After a rate limit, wait for the appropriate reset before running the suite again.

## Python use and development

```python
from promptintel_cli import Client

client = Client()  # reads PROMPTINTEL_API_KEY
# Or Client(profile="enterprise"); the environment key still takes precedence.
response = client.request("GET", "/agent-feed", params={"severity": "high"})
print(response.payload)
```

Use `service="scanner"` for scanner endpoints. `Client.request()` is a low-level primitive; interactive consent is a CLI feature, so applications using it must obtain any necessary approval themselves. `Response.raw` contains original bytes and `Response.headers` contains original headers: handle these as untrusted data and do not log them indiscriminately. Formatted CLI output applies the redaction and display protections described above.

Run the offline test suite:

```sh
python3 -m unittest discover -v
```

Tests use simulated HTTP responses, fake credentials, and temporary files. They cover routes, query encoding, POST/PATCH bodies, both services, output formats, consent, local file restrictions, redaction, redirects, HTTP/API errors, 304/429 handling, headers, checksum-protected downloads, doctor diagnostics, file/stdin indicators, policy exit codes, bounded pagination and portable builds. Credential tests use an in-memory backend and cover precedence, hidden input, unsafe-backend refusal, locked/missing stores and live-runner profile loading. Offline tests never access your real keychain, make submissions or consume live scan/check quota.

