# Formal Investigation Process

Use phase gates to prevent premature deep dives and unsupported findings.

## P0: Intake

Capture the objective, input kind, artifact or target identifiers, constraints, available access, expected deliverable, and success condition. Hash every local input before conversion or extraction. For a prompt-only case, explicitly name the first evidence gap.

Exit when the objective and inputs are unambiguous enough to choose a first observation.

## P1: Rapid Map

Classify the artifact or surface, audit only relevant tools, and build a compact attack-surface map. Prefer metadata, protocol hierarchy, file inventory, strings/imports, manifests, and endpoint enumeration over deep decompilation.

Score candidate lanes by relevance, evidence availability, cost, and expected information gain. Select one primary lane and keep at most two alternatives.

Exit when one lane and its first discriminating action are selected.

## P2: Hypothesis Backlog

Create a bounded hypothesis for each meaningful lead. State:

- claimed mechanism;
- supporting evidence IDs;
- strongest competing explanation;
- expected positive and negative signals;
- one cheapest validation action;
- dependency and stop condition.

Rank no more than three hypotheses. Do not use severity as a substitute for evidence.

Exit when every active hypothesis has a test that can promote or reduce it.

## P3: Targeted Validation

Execute one validation at a time. Preserve inputs and raw outputs. Record runtime state such as session, ECU mode, ignition state, process version, address-space layout, device build, user role, or authentication state when it changes interpretation.

Use a second evidence source for high-impact conclusions: capture plus code, static plus dynamic, request plus server log, or two independent parsers.

Exit when the success/failure criteria have been observed or the exact missing dependency is known.

## P4: Conclusion and Next Operations

Convert supported hypotheses into bounded conclusions or findings. Include affected component, input, reachable path, preconditions, observed behavior, evidence IDs, confidence, and remaining boundary.

Order the next three operations by information gain per cost. Stop when the objective is answered, evidence conflicts require reassessment, a required dependency is absent, or the next action exceeds case constraints.
