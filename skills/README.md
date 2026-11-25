<!-- SPDX-License-Identifier: Apache-2.0 -->

# NVAT agent skills

These skills help coding agents install the NVIDIA Attestation SDK, perform
CoRIM attestation, and diagnose failures. CoRIM is the primary workflow;
legacy attestation is covered when needed for an existing deployment.

| Skill | Use it for |
| --- | --- |
| [nvat-install-and-guide](nvat-install-and-guide/SKILL.md) | OS/architecture detection, installation choices, and CLI/C/Rust documentation questions |
| [nvat-corim-attestation](nvat-corim-attestation/SKILL.md) | CMW collection, CoRIM appraisal, policy selection, and EAR interpretation |
| [nvat-troubleshooting](nvat-troubleshooting/SKILL.md) | Installation/linking errors, field failures, runtime/reference comparison, indices, and OIDs |

Each folder can be used on its own and includes its references and evals.
The skills use official public documentation and public source links. They
do not require internal tools, a particular agent harness, or another NVAT
skill to be installed.

## Version compatibility

CoRIM support is experimental. Check `nvattest version` and the relevant
subcommand help before following a command example. Public `main`, hosted
`/latest/` documentation, and downloadable packages can expose different
interfaces. Select a public release or commit whose capabilities match the
target environment, and keep CLI and native-library versions compatible.

These skills do not specify a minimum public release covering every
workflow. Confirm the selected release's capabilities and use its official
download matrix to determine OS/architecture support. The agent's own host
does not establish support.

## Evaluate the skills

Each `evals/evals.json` is an array of realistic user questions with
`expected_skill`, `expected_script`, `ground_truth`, and `expected_behavior`.
This follows an evaluation shape used in the public NVIDIA skills catalog.
For publication requirements, see the
[NVIDIA Skills documentation](https://docs.nvidia.com/skills).
The datasets contain evaluation inputs; results are recorded in each skill's
`BENCHMARK.md`.

Run each case in a fresh agent session with the skill package and the inputs
named in the question. Keep ground truth and expected behavior available only
to the evaluator. The agent should have the same docs, tools, and environment
in runs with and without the skill. Record tool calls, outputs, missing inputs,
and pass/fail for each expected behavior. Cases that lack a real target must
be scored on diagnosis and next steps, not a claim of successful installation.

The troubleshooting measurement cases include synthetic records directly in
their questions. Matching records are also available in the
[fixtures directory](nvat-troubleshooting/evals/fixtures/). They test byte
formatting and provenance. They are not CMWs or signed evidence and must not
be submitted as proof of a hardware appraisal.

Behavioral exercises do not replace live integration tests. When validating
a supported release, exercise installation on its claimed target platforms,
GPU collection on a supported system, appraisal against known references,
and negative cases with the intended policy. Also test a transported EAR against the actual signer/JWKS
and challenge flow.

The skill content is licensed under Apache-2.0; see the repository's
[license](../LICENSE).
