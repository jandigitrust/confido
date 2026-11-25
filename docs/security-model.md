# Confido 0.2 security model

Confido appraises evidence from an Azure confidential VM against a policy and
reference values selected by its caller. It returns an **evidence-only** result.
The application that uses the result must separately authenticate its network
peer and decide whether to release credentials or send work. This is a
development revision, not a production certification.

The trusted execution environment (TEE) in this profile is an AMD SEV-SNP
protected virtual machine. Attestation checks claims about that VM; it does
not certify every program or service that may run inside or outside it.

**Genoa** and **Milan** are AMD EPYC processor generations. The current local
test VM uses Genoa. The selected generation determines the AMD certificate
chain and platform-specific reference enrollment; a Milan demo policy is not
interchangeable with a Genoa policy.

The design uses the role separation in the
[RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html). Its repository
boundaries do not exactly mirror those roles:

| Role | In this project | Responsibility |
| --- | --- | --- |
| Attester | [JAN Attestor](https://github.com/jandigitrust/attestor) | Collects the hardware report, vTPM quote, IMA log, and HTTPS certificate; responds to a caller's challenge. |
| Verifier | Confido `verifier/`, using the shared [Evidence](https://github.com/teraveri/evidence) crates | Checks signatures, bindings, platform policy, and measurements against caller-approved inputs. It makes no network connection. |
| Reference publisher and registry | GENXT's recorded publisher statement and the [Teraveri registry](https://github.com/teraveri/reference-value-registry) | Identify and preserve an exact candidate measurement manifest. The caller decides whether to trust that publisher and reference. |
| Relying application | [Confidential AI example](https://github.com/genxnetwork/confidential-ai-example) | Checks the actual HTTPS peer and decides whether evidence is sufficient to send credentials or application traffic. |

An AMD certificate chain endorses the hardware report. GENXT's signature on a
reference manifest has a different purpose: it identifies the publisher of
those **proposed expected values**. Neither the signature nor registry hosting
certifies that the measured VM or application is safe.

The collector's response and network-fetched certificates and reference bytes
are inputs to check, not authorities that may set policy. The example's
enrollment tool checks the publisher statement before producing a pinned policy;
Confido checks the supplied reference bytes against that policy but does not
fetch or approve a publisher itself.

## What the verifier checks

1. **Local trust choices.** Before appraising evidence, the caller supplies a
   policy that pins the AMD root for the selected processor product, a permitted
   launch measurement, minimum firmware security versions, and an exact
   reference identity and digest. The caller also supplies the expected random
   challenge and an evaluation time. Evidence or a registry response cannot
   choose these trust anchors.
2. **Hardware and vTPM link.** Confido validates the AMD ARK → ASK → VCEK
   certificate path and the SEV-SNP report signature. The report authenticates
   Azure runtime metadata (the HCL section) containing the virtual TPM's
   attestation public key (AK). This links a subsequent TPM quote to the
   hardware report; it does not by itself approve the guest workload. The
   [Azure guest-attestation design](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design)
   describes this relationship.
3. **Challenge and measurements.** The AK signs a TPM quote. Confido checks that
   the quote commits to the caller's challenge, the collector's certificate,
   and the supplied IMA log; it checks the quoted PCR values against the log
   and compares the measured entries with the pinned reference. The supported
   `azure-snp-vtpm-ima/1` profile and its exact wire-v1 binding are specified in
   the [Evidence protocol](https://github.com/teraveri/evidence/blob/main/protocol/README.md).
4. **Separate application decision.** A successful verifier result says that
   the supplied evidence satisfied this policy at the supplied evaluation
   time. The native example then checks that its actual HTTPS peer presents
   the appraised certificate at the intended hostname, enforces its challenge
   deadline, and makes its own admission decision. A saved archive can be
   replayed for analysis but cannot recreate a live admission. The local result
   is a structured record, not a signed attestation token.

In these steps, **ARK** and **ASK** are AMD's root and SEV signing-key
certificates; **VCEK** is the chip-specific certificate used to verify the
SEV-SNP report. A **vTPM** is the VM's virtual Trusted Platform Module, and its
**AK** (Attestation Key) signs a **quote**: a statement about selected **PCRs**
(Platform Configuration Registers) and a challenge. Linux **IMA** (Integrity
Measurement Architecture) records measured files or modules; its log must
agree with the quoted PCR state and an approved **reference value** (the
expected measurement). The **boot aggregate** is the initial IMA entry
summarising boot measurements. **TCB** (Trusted Computing Base) here denotes the
security-version components compared with the policy's minimum. These are
distinct checks: a valid signature does not make the measured state acceptable.

## What a passing result does not establish

- The enrolled Genoa stage reference covers one boot aggregate and 44 kernel
  modules. It does not measure application code, configuration, models, GPU
  state, or external inference.
  [Azure's workload-attestation guidance](https://learn.microsoft.com/en-us/azure/confidential-computing/how-to-attest-linux-workload)
  likewise distinguishes VM attestation from workload approval.
- Certificate binding does not bind evidence to a specific TLS session or
  prevent relay. Guest collector behavior, TLS key custody, and changes after
  appraisal remain trust assumptions.
- The challenge makes the TPM quote responsive to this request; the retrieved
  SNP report need not have been generated for this request. The caller owns
  nonce generation, deadlines, and reuse prevention.
- The enrolled minimum TCB is an operator decision. Confido does not
  automatically check AMD revocation lists or security advisories. The current
  stage used a locally approved manual GENXT publisher statement and a
  synthetic downstream responder. Public deployment, external inference, and
  independent reproduction have not been accepted.

For exact implemented claims and test limits, use the
[coverage matrix](revision/coverage.md). The
[dated acceptance records](revision/acceptance-genoa-direct-20261123.md)
identify the source and artifacts actually exercised; the
[independent rerun checklist](revision/rerun.md) describes what a separate
reviewer should repeat.
