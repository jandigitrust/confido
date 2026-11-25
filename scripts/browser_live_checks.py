"""Opt-in live evidence acceptance for a packaged Chromium extension.

Deployment origins, trust policies and expected results come from caller-owned
cases. No credentials, chat requests or private evidence archives are used.
"""

import argparse
import ipaddress
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from browser_extension import installed_page

STATUSES = {
    "verified", "invalid_evidence", "policy_mismatch",
    "unsupported_profile", "incomplete_input",
}
MAX_INPUT_BYTES = 64 * 1024
DATA_HOSTS = ("https://kdsintf.amd.com/*", "https://api.github.com/*")


class CheckInputError(ValueError):
    """A safe, locally generated configuration diagnostic."""


class AcceptanceFailure(AssertionError):
    """A safe verdict diagnostic that contains no browser/server content."""


@dataclass(frozen=True)
class LiveCase:
    """A deployment expectation and a snapshot of its caller-selected policy."""

    name: str
    origin: str
    policy_path: Path
    policy_bytes: bytes
    expected_status: str
    expected_reason: str | None


def read_input(path):
    """Bound local configuration before parsing or opening the browser."""
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise CheckInputError("Browser check input exceeds 64 KiB")
    return data


def load_cases(path):
    """Resolve all policies relative to the case file, never to a sibling checkout."""
    path = path.resolve()
    records = json.loads(read_input(path))
    if not isinstance(records, list) or not 1 <= len(records) <= 32:
        raise CheckInputError("Expected one to 32 live browser cases")
    cases = []
    names = set()
    required = {"name", "origin", "policy", "expected_status"}
    for record in records:
        if (
            not isinstance(record, dict)
            or not required <= record.keys()
            or record.keys() - required - {"expected_reason"}
        ):
            raise CheckInputError("Unexpected live browser case fields")
        if not all(isinstance(record[key], str) for key in required):
            raise CheckInputError("Required live browser case values must be strings")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", record["name"]):
            raise CheckInputError("Case name must be a short identifier")
        if record["name"] in names:
            raise CheckInputError("Live browser case names must be unique")
        names.add(record["name"])
        origin = urlsplit(record["origin"])
        if (
            origin.scheme != "https" or not origin.hostname
            or origin.username or origin.password
            or origin.path or origin.query or origin.fragment
        ):
            raise CheckInputError("Case origin must be a bare HTTPS origin without a trailing slash")
        if (
            origin.port is not None
            or record["origin"] != f"https://{origin.netloc}"
            or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                       for label in origin.hostname.split("."))
        ):
            raise CheckInputError("Case origin must match a packaged HTTPS DNS origin without a port")
        if record["expected_status"] not in STATUSES:
            raise CheckInputError("Unknown expected evidence status")
        reason = record.get("expected_reason")
        if "expected_reason" in record and not isinstance(reason, str):
            raise CheckInputError("Expected reason must be a string")
        policy = (path.parent / record["policy"]).resolve(strict=True)
        policy_bytes = read_input(policy)
        if not isinstance(json.loads(policy_bytes), dict):
            raise CheckInputError("Expected a JSON policy object")
        cases.append(LiveCase(
            name=record["name"], origin=record["origin"],
            policy_path=policy, policy_bytes=policy_bytes,
            expected_status=record["expected_status"], expected_reason=reason,
        ))
    return cases


def prepare_extension(source, destination, cases, *, pregrant_hosts=False):
    """Copy the package; optionally pregrant only its declared optional hosts.

    Pregranting is a delivery-test mode and does not test permission consent.
    """
    manifest = json.loads((source / "manifest.json").read_text())
    optional = manifest.get("optional_host_permissions", [])
    if any(case.origin + "/*" not in optional for case in cases):
        raise CheckInputError("Case origin is absent from the extension's optional host permissions")
    required_hosts = list(dict.fromkeys([*(case.origin + "/*" for case in cases), *DATA_HOSTS]))
    granted = manifest.get("host_permissions", [])
    if any(host not in optional and host not in granted for host in required_hosts):
        raise CheckInputError("Extension is missing a required collection host permission")
    shutil.copytree(source, destination)
    if pregrant_hosts:
        manifest["host_permissions"] = list(dict.fromkeys(
            granted + required_hosts
        ))
        (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def check_result(case, result):
    """Require the expected evidence verdict without claiming peer or app admission."""
    if result.get("status") != case.expected_status:
        raise AcceptanceFailure(f"{case.name}: unexpected evidence status")
    if result.get("scope") != "evidence_only" or "application_admitted" in result:
        raise AcceptanceFailure(f"{case.name}: unexpected application admission claim")
    if case.expected_reason is not None and result.get("reason") != case.expected_reason:
        raise AcceptanceFailure(f"{case.name}: unexpected evidence reason")


def resolver_rules(mappings, cases):
    """Build explicit Chromium mappings only for caller-selected evidence hosts.

    Local/private addresses are valid test destinations. TLS still authenticates
    the original hostname, and AMD/GitHub resolution is not overridden here.
    """
    allowed = {urlsplit(case.origin).hostname for case in cases}
    data_hosts = {urlsplit(pattern).hostname for pattern in DATA_HOSTS}
    resolved = {}
    for mapping in mappings:
        host, separator, address = mapping.partition("=")
        host = host.lower()
        if host in data_hosts:
            raise CheckInputError("--resolve cannot override AMD KDS or GitHub")
        if not separator or host not in allowed or host in resolved:
            raise CheckInputError("Each --resolve must name a unique selected case host as HOST=IP")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            raise CheckInputError("--resolve requires a literal IP address") from None
        if parsed.version == 6 and parsed.scope_id is not None:
            raise CheckInputError("--resolve does not support scoped IPv6 addresses")
        resolved[host] = parsed
    rules = []
    for host, address in resolved.items():
        literal = f"[{address}]" if address.version == 6 else str(address)
        rules.append(f"MAP {host} {literal}")
    return ", ".join(rules) if rules else None


def run_checks(extension, cases, *, pregrant_hosts=False, headed=False, host_resolver_rules=None):
    """Exercise real live collection; no retries or certificate-error bypasses."""
    from playwright.sync_api import sync_playwright

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / "extension"
        prepare_extension(extension, package, cases, pregrant_hosts=pregrant_hosts)
        mode = "pregranted hosts in a temporary copy" if pregrant_hosts else "unchanged package"
        print("Permission mode: " + mode, flush=True)
        print("DNS mode: " + ("explicit case-host mappings" if host_resolver_rules else "system resolver"), flush=True)
        with sync_playwright() as playwright:
            context, page = installed_page(
                playwright, package, root / "profile", headless=not headed,
                host_resolver_rules=host_resolver_rules,
            )
            try:
                for case in cases:
                    print(f"{case.name}: collecting live evidence", flush=True)
                    # Each page gets a new worker and cannot reuse a previous result.
                    page.reload()
                    page.locator("#policy").set_input_files({
                        "name": case.policy_path.name,
                        "mimeType": "application/json", "buffer": case.policy_bytes,
                    })
                    page.locator("#origin").select_option(case.origin)
                    page.locator("#live").click()
                    page.wait_for_function("""() =>
                        !document.querySelector('#save').disabled ||
                        document.querySelector('#status').textContent !== 'Verifying…'
                    """, timeout=150000)
                    if page.locator("#save").is_disabled():
                        # UI errors can contain remote content; keep them out of logs.
                        raise AcceptanceFailure(f"{case.name}: live collection failed before a result")
                    check_result(case, json.loads(page.locator("#result").inner_text()))
                    print(f"{case.name}: {case.expected_status}; local WASM, browser TLS")
            finally:
                context.close()


def main():
    """Validate caller inputs before loading optional Playwright dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension-dir", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--headed", action="store_true",
                        help="Show Chromium for operator-driven permission consent")
    parser.add_argument("--pregrant-hosts", action="store_true",
                        help="Bypass consent in a temporary test copy; not a consent UI test")
    parser.add_argument("--resolve", action="append", default=[], metavar="HOST=IP",
                        help="Override a selected evidence host in this Chromium context; repeat for multiple hosts")
    args = parser.parse_args()
    try:
        cases = load_cases(args.cases)
        rules = resolver_rules(args.resolve, cases)
        run_checks(args.extension_dir.resolve(strict=True), cases,
                   pregrant_hosts=args.pregrant_hosts, headed=args.headed,
                   host_resolver_rules=rules)
    except (CheckInputError, AcceptanceFailure) as error:
        print(f"Live browser acceptance failed: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Browser/server messages can contain remote content. Do not echo them.
        print(f"Live browser acceptance failed ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
