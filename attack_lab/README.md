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

## Interpreting results

Scenario input is untrusted test data. The runner sends it through the local analysis service as text; it never executes it as a command or tool, and never makes network or database requests from scenario contents.

Each result reports two separate outcomes:

- **Detector result:** the nested detection category, severity, and recommended action, compared with the scenario expectation. Severity passes when it meets or exceeds the expected minimum; the recommended action must match exactly.
- **Pipeline risk result:** the SecurityService/Risk Engine score, severity, and action. The current compatibility wrapper leaves the threat category unassessed, so the Risk Engine can fail closed with a score of 100 and `BLOCK`, independently of the detector result.

`overall_passed` reflects whether the detector result matches the scenario expectation. It does not combine that check with the separate pipeline risk result.

The report intentionally excludes raw scenario input, request IDs, timestamps, secrets, and tool arguments. It contains only scenario identifiers and safe decision metadata.
