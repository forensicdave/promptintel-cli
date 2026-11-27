# Changelog

## [0.1.0] - 2026-11-27

### Added

- CLI coverage for the documented PromptIntel REST and Agent Scanner endpoints.
- JSON, Markdown and text output; native NOVA/CSV downloads; safe debug and verbose logging.
- `doctor` for API health, authentication, account plan and scanner quotas.
- Optional `keyring` installation extra, `auth set/status/delete` commands with hidden key entry, and explicit `--profile` selection for macOS Keychain and Linux credential stores.
- Credential-source/profile diagnostics in `doctor`, `make setup-keyring`, and keyring-backed live tests via `make test-live LIVE_AUTH=keyring`.
- Indicator input from UTF-8 files or stdin using `check --input`, with text and JSON formats.
- Opt-in `--fail-on` policies for indicator checks and scan verdicts, using exit code 6.
- Bounded `--all --max-pages` collection for numbered pages, offsets and cursors, retaining every response envelope.
- MIT licence, included in the portable executable, wheel and source distribution.
- Make targets for development, tests, release builds and installation; portable executable, wheel, source archive and checksums.
- Offline tests and an opt-in Community/Enterprise live matrix with focused reruns and sanitized reports.
- README Quickstart, contents navigation and worked investigation, skill-review and CI examples, including illustrative Community/Enterprise results. Build and live-test guidance follows everyday usage.

### Behavior and safeguards

- Endpoint commands still make one request by default and use exit code 0 for request success, regardless of verdict. `doctor` makes up to three read-only requests.
- `--all` defaults to five requests, with a hard maximum of 100; bounded results state whether collection is complete.
- No automatic retries, including on HTTP 429; redirects are not followed.
- Uploads and submissions require explicit consent. Hash lookups send only hashes.
- Environment credentials take precedence over explicitly selected keyring profiles. Base installations remain dependency-free; public/local commands never access the keyring.
- Credentials are redacted from formatted output and logs. Keyring operations refuse plaintext, null and unknown backends and never fall back to a credential file.
- Returned threat content remains untrusted data. Unknown verdicts do not mean safe, and static scan signals are not deep-review verdicts.

[0.1.0]: https://github.com/forensicdave/promptintel-cli
