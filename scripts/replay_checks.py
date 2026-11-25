"""Replay real hardware evidence with negative mutations, without network access.

The input must be a privately retained bundle with a valid SNP signature.
This script never grants live application access.
"""

import argparse
import copy
import hashlib
import json
import math
import time
from pathlib import Path

import confido_client
from archive_inputs import arguments, decode, encode, migrate

PIPELINE = (
    "endorsements",
    "snp_signature",
    "vcek_correspondence",
    "platform_policy",
    "hcl_key",
    "quote_signature",
    "quote_binding",
    "quoted_pcrs",
    "reference",
    "ima_reference",
    "boot_aggregate",
    "pcr10",
)

EXPECTED_FAILURE_STAGE = {
    "challenge_replay": "quote_binding",
    "reference_content": "reference",
    "changed_snp_signature": "snp_signature",
    "changed_vcek_chip": "snp_signature",
    "ca_certificate_after_signed_report": "certificate",
    "snp_signature_before_ca_certificate": "snp_signature",
    "quote_signature_before_ca_certificate": "quote_signature",
    "changed_quote_signature": "quote_signature",
    "changed_pcr": "quoted_pcrs",
    "changed_ima": "quote_binding",
    "reference_ima_content": "ima_reference",
    "reference_ima_order": "ima_reference",
    "reference_pcr10": "pcr10",
    "unsigned_module_order": "pcr10",
}


class ReplayRunner:
    def __init__(self, bundle, policy):
        self.bundle = bundle
        self.policy = policy
        self.records = []

    @staticmethod
    def input_bytes(archive, name):
        return decode(archive["inputs"][name])

    @staticmethod
    def set_input(archive, name, value):
        archive["inputs"][name] = encode(value)

    def change_json_input(self, archive, name, edit):
        value = json.loads(self.input_bytes(archive, name))
        edit(value)
        self.set_input(archive, name, json.dumps(value, separators=(",", ":")).encode())

    def change_report(self, archive, edit):
        self.change_json_input(archive, "report", edit)

    def flip_snp_byte(self, archive, offset):
        def edit(report):
            report["evidence"]["report"][offset] ^= 1

        self.change_report(archive, edit)

    def substitute_ca_certificate(self, archive, _policy):
        first = (
            self.input_bytes(archive, "amd_chain").split(
                b"-----END CERTIFICATE-----", 1
            )[0]
            + b"-----END CERTIFICATE-----\n"
        )
        self.change_report(
            archive, lambda report: report.update(certificate=list(first))
        )

    def change_reference(self, archive, policy, edit):
        reference = json.loads(self.input_bytes(archive, "reference"))
        edit(reference)
        raw = json.dumps(reference, separators=(",", ":")).encode()
        self.set_input(archive, "reference", raw)
        policy["reference"]["sha256"] = hashlib.sha256(raw).hexdigest()

    def flip_quote_signature(self, archive, _policy):
        def edit(report):
            signature = report["evidence"]["quote"]["signature"]
            signature[0] ^= 1

        self.change_report(archive, edit)

    def flip_quoted_pcr(self, archive, _policy):
        def edit(report):
            pcr = report["evidence"]["quote"]["pcr_banks"][0]["pcr_values"][10]
            pcr[0] ^= 1

        self.change_report(archive, edit)

    def substitute_hcl_key(self, archive, _policy):
        report = json.loads(self.input_bytes(archive, "report"))
        raw = bytearray(report["evidence"]["report"])
        size = int.from_bytes(raw[1232:1236], "little")
        metadata = json.loads(raw[1236 : 1236 + size])
        key = next(item for item in metadata["keys"] if item.get("kid") == "HCLAkPub")
        offset = raw.find(key["n"].encode(), 1236) + 10
        raw[offset] = ord("A") if raw[offset] != ord("A") else ord("B")
        report["evidence"]["report"] = list(raw)
        self.set_input(
            archive, "report", json.dumps(report, separators=(",", ":")).encode()
        )

    def run(self, name, mutate, expected):
        archive = copy.deepcopy(self.bundle)
        policy = copy.deepcopy(self.policy)
        mutate(archive, policy)
        try:
            result = confido_client.verify(
                *arguments(archive, json.dumps(policy).encode())
            )
        except ValueError:
            if expected not in ("invalid_nonce", "input_too_large"):
                raise
            self.records.append(
                {
                    "id": name,
                    "expected": expected,
                    "observed": "api_input_error",
                }
            )
            return

        assert result["reason"] == expected, (
            name,
            result["reason"],
            result["checks"][-1],
        )
        assert result["scope"] == "evidence_only"
        assert "application_admitted" not in result
        passed = [
            check["stage"] for check in result["checks"] if check["status"] == "passed"
        ]
        assert passed == list(PIPELINE[: len(passed)]), (name, passed)
        if name in EXPECTED_FAILURE_STAGE:
            assert result["checks"][-1]["stage"] == EXPECTED_FAILURE_STAGE[name], (
                name,
                result["checks"][-1],
            )
        if result["status"] == "verified":
            assert passed == list(PIPELINE)
            assert result["coverage"]["ima_entries"] > 0
        else:
            assert result["coverage"]["ima_entries"] == 0
        bound = "quote_binding" in passed
        assert all(value is bound for value in result["bindings"].values())
        assert ("certificate_sha256" in result["verified_artifacts"]) is bound
        assert ("vtpm_key_sha256" in result["verified_artifacts"]) is (
            "hcl_key" in passed
        )
        self.records.append(
            {
                "id": name,
                "expected": expected,
                "observed": result["reason"],
                "last_stage": result["checks"][-1]["stage"],
                "completed_stages": passed,
            }
        )


def run_mutations(runner):
    run = runner.run
    run("original_hardware_evidence", lambda archive, policy: None, "reference_match")
    run(
        "challenge_replay",
        lambda archive, policy: archive["context"].update(
            expected_nonce_base64=encode(bytes(32))
        ),
        "quote_binding_invalid",
    )
    run(
        "invalid_nonce",
        lambda archive, policy: archive["context"].update(expected_nonce_base64="bad!"),
        "invalid_nonce",
    )
    run(
        "reference_content",
        lambda archive, policy: runner.set_input(
            archive, "reference", runner.input_bytes(archive, "reference") + b" "
        ),
        "reference_digest_mismatch",
    )
    # Saved result and origin are untrusted replay metadata, including for v1 inputs.
    run(
        "stored_result_substitution",
        lambda archive, policy: archive.update(
            verification={"reference": {"commit": "0" * 40}, "status": "verified"}
        ),
        "reference_match",
    )
    run(
        "origin_substitution",
        lambda archive, policy: archive.update(origin="https://other.invalid"),
        "reference_match",
    )
    run(
        "unsupported_wire",
        lambda archive, policy: runner.change_report(
            archive, lambda report: report.update(wireVersion=2)
        ),
        "unsupported_wire_version",
    )
    run(
        "untrusted_root",
        lambda archive, policy: policy["platform"].update(ark_sha256="0" * 64),
        "endorsement_chain_invalid",
    )
    run(
        "launch_policy",
        lambda archive, policy: policy["platform"].update(launch_measurement="0" * 96),
        "platform_policy_mismatch",
    )
    run(
        "minimum_tcb",
        lambda archive, policy: policy["platform"].update(minimum_tcb=[255] * 4),
        "platform_policy_mismatch",
    )
    run(
        "malformed_hcl",
        lambda archive, policy: runner.change_report(
            archive, lambda report: report["evidence"].update(report=[0])
        ),
        "malformed_hcl",
    )
    run(
        "changed_snp_signature",
        lambda archive, policy: runner.flip_snp_byte(archive, 32 + 672),
        "snp_signature_invalid",
    )
    run(
        "changed_vcek_chip",
        lambda archive, policy: runner.flip_snp_byte(archive, 32 + 416),
        "snp_signature_invalid",
    )
    run(
        "ca_certificate_after_signed_report",
        runner.substitute_ca_certificate,
        "ca_certificate_unsupported",
    )

    def signature_and_ca(archive, policy):
        runner.substitute_ca_certificate(archive, policy)
        runner.flip_snp_byte(archive, 32 + 672)

    run(
        "snp_signature_before_ca_certificate",
        signature_and_ca,
        "snp_signature_invalid",
    )

    def quote_and_ca(archive, policy):
        runner.substitute_ca_certificate(archive, policy)
        runner.flip_quote_signature(archive, policy)

    run(
        "quote_signature_before_ca_certificate",
        quote_and_ca,
        "quote_binding_invalid",
    )
    run(
        "reference_ima_content",
        lambda archive, policy: runner.change_reference(
            archive,
            policy,
            lambda reference: reference["ima_measurements"][1].update(
                filedata_hash="0" * 64
            ),
        ),
        "measurement_mismatch",
    )
    run(
        "reference_ima_order",
        lambda archive, policy: runner.change_reference(
            archive, policy, lambda reference: reference["ima_measurements"].reverse()
        ),
        "measurement_mismatch",
    )
    run(
        "reference_pcr10",
        lambda archive, policy: runner.change_reference(
            archive, policy, lambda reference: reference.update(pcr10_sha256="0" * 64)
        ),
        "measurement_mismatch",
    )
    run(
        "unsigned_module_order",
        lambda archive, policy: runner.change_report(
            archive,
            lambda report: report["evidence"]["module_load_order"]["order"].reverse(),
        ),
        "measurement_mismatch",
    )
    run(
        "substituted_hcl_attestation_key",
        runner.substitute_hcl_key,
        "hcl_binding_invalid",
    )
    run("changed_quote_signature", runner.flip_quote_signature, "quote_binding_invalid")
    run("changed_pcr", runner.flip_quoted_pcr, "quote_binding_invalid")
    run(
        "changed_ima",
        lambda archive, policy: runner.change_report(
            archive,
            lambda report: report["evidence"]["ima_measurements"][0].update(
                filedata_hash="0" * 64
            ),
        ),
        "quote_binding_invalid",
    )
    run(
        "oversized_reference",
        lambda archive, policy: runner.set_input(
            archive, "reference", b" " * (4 * 1024 * 1024 + 1)
        ),
        "input_too_large",
    )


def check_endorsement_time(runner):
    for label, evaluation_time in (
        ("endorsement_not_yet_valid", 0),
        ("endorsement_expired", 7258118400),
    ):
        result = confido_client.verify(
            *arguments(
                runner.bundle,
                json.dumps(runner.policy).encode(),
                at=evaluation_time,
            )
        )
        assert result["reason"] == "endorsement_chain_invalid", (label, result)
        assert "application_admitted" not in result
        runner.records.append(
            {
                "id": label,
                "expected": "endorsement_chain_invalid",
                "observed": result["reason"],
            }
        )


def benchmark(bundle, policy, samples):
    times = []
    for _ in range(samples):
        started = time.perf_counter()
        result = confido_client.verify(
            *arguments(bundle, json.dumps(policy).encode())
        )
        assert result["status"] == "verified"
        times.append((time.perf_counter() - started) * 1000)
    p95 = sorted(times)[math.ceil(len(times) * 0.95) - 1]
    return times, p95


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--at", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()

    bundle = migrate(json.loads(args.bundle.read_text()), args.at)
    policy = json.loads(args.policy.read_text())
    runner = ReplayRunner(bundle, policy)
    run_mutations(runner)
    check_endorsement_time(runner)
    times, p95 = benchmark(bundle, policy, args.samples)

    output = {
        "mode": "hardware_evidence_replay",
        "runtime": confido_client.build_info(),
        "evaluation_time": args.at,
        "tests": runner.records,
        "samples": len(times),
        "local_appraisal_ms": times,
        "p95_ms": p95,
        "target_ms": 3000,
        "target_met": p95 <= 3000,
        "timing_scope": (
            "All inputs already local; includes caller serialization and Rust checks; "
            "excludes collection and network"
        ),
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        f"{len(runner.records)} replay cases passed; "
        f"{len(times)} local appraisals, p95={p95:.2f} ms"
    )


if __name__ == "__main__":
    main()
