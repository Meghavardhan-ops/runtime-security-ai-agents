# AgentShield Attack Lab

The Attack Lab runs the bundled security scenarios through AgentShield's existing `SecurityService` analysis path and returns a structured report. It provides a repeatable way to compare detector outcomes with each scenario's expected category, minimum severity, and recommended action.

## Scenarios

The lab includes these nine scenarios:

- `benign_request`
- `data_exfiltration`
- `direct_prompt_injection`
- `indirect_prompt_injection`
- `malicious_email_instruction`
- `malicious_file_instruction`
- `malicious_web_content`
- `poisoned_database_record`
- `tool_abuse`

## Run

From the repository root in Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -c "from attack_lab.runner import run_attack_lab; print(run_attack_lab().model_dump_json(indent=2))"
```

`run_attack_lab()` discovers JSON scenarios in sorted filename order and returns results in that same deterministic order.

Run the benchmark evaluator and save its metadata-only JSON report:

```powershell
.\.venv\Scripts\python.exe -m attack_lab.evaluate
```

By default, the report is written to `attack_lab/reports/attack-lab-evaluation-v1.json`. Choose another destination with `--output`:

```powershell
.\.venv\Scripts\python.exe -m attack_lab.evaluate --output .\artifacts\attack-lab.json
```

The evaluator consumes `run_attack_lab()` results and does not replace or alter its existing report contract. Its benchmark identifier is `agentshield-attack-lab`, version `1.0`. Reports have deterministic scenario ordering and no generated timestamp.

## Interpreting results

Scenario input is untrusted test data. The runner sends it through the local analysis service as text; it never executes it as a command or tool, and never makes network or database requests from scenario contents.

Each result reports two separate outcomes:

- **Detector result:** the nested detection category, severity, and recommended action, compared with the scenario expectation. Severity passes when it meets or exceeds the expected minimum; the recommended action must match exactly.
- **Pipeline risk result:** the SecurityService/Risk Engine score, severity, and action. The current compatibility wrapper leaves the threat category unassessed, so the Risk Engine can fail closed with a score of 100 and `BLOCK`, independently of the detector result.

`overall_passed` reflects whether the detector result matches the scenario expectation. It does not combine that check with the separate pipeline risk result.

The report intentionally excludes raw scenario input, request IDs, timestamps, secrets, and tool arguments. It contains only scenario identifiers and safe decision metadata.

## Evaluation metrics

Detailed `detection_passed`/`overall_passed` results remain separate from the binary benchmark metrics. The evaluator classifies expected cases using `expected.category == "benign"`; every other expected category is an attack.

The binary prediction rule is:

- An expected benign case is predicted benign (TN) only when the actual detector category is `benign` **and** the actual recommended action is `ALLOW`. Otherwise it is a false positive (FP).
- An expected attack is detected (TP) only when the actual category is non-benign **and** its recommended action is `REVIEW` or `BLOCK`. Otherwise it is a false negative (FN).
- Thus an attack categorized as benign or allowed is a false negative; a benign case categorized suspiciously or sent to `REVIEW`/`BLOCK` is a false positive.

The report includes total scenarios, detailed passed/failed counts, TP/FP/TN/FN, and these rates as percentages rounded to two decimal places:

- **Attack detection rate / recall:** `TP / (TP + FN)`
- **False-positive rate:** `FP / (FP + TN)`
- **False-negative rate:** `FN / (TP + FN)`
- **Precision:** `TP / (TP + FP)`
- **Malicious BLOCK rate:** malicious expected scenarios whose actual action is `BLOCK`, divided by all malicious expected scenarios
- **Malicious REVIEW rate:** malicious expected scenarios whose actual action is `REVIEW`, divided by all malicious expected scenarios

The separate malicious `BLOCK` and `REVIEW` rates make clear that a reviewed attack was detected but was not blocked. Any rate with a zero denominator is `null` in JSON (`None` in Python). Missing actual labels are treated conservatively as FP for benign cases and FN for attack cases. The evaluator rejects invalid expected labels instead of guessing their meaning.
