# SA-ZTRASF — Reproducible Python verification and synthetic comparison

## Run
Python 3.9+; no third-party packages needed for the core experiments:
```
python verify_policy.py
python run_simulation.py
```
The included PNG was generated separately with Matplotlib; the scripts above regenerate all CSV and JSON data.

## Completed tests
- 16 exhaustive binary combinations of A = I AND S AND P AND O
- Seven predefined supervisory scenarios
- Four invalid-input rejection cases
- **27/27 checks pass**
- 3,000 predefined synthetic requests (six classes × 500), evaluated against three simplified policies = **9,000 decisions**.
- Adversarial rejection among 2,500 requests: conventional 500 (20%), simplified Zero Trust 2,000 (80%), SA-ZTRASF 2,500 (100%). All 500 legitimate requests are permitted by each policy.

## Critical scientific limitations
The simulator assigns identity, session, permission and operational-state flags directly from each scenario. It does **not** detect credential compromise, replay, hijacking, or unsafe operating conditions. Five hundred copies of each condition vector are **not independent attack trials**. Rejection rates follow deterministically from chosen flags, policies and class balance. Baselines are simplified analytical models, **not representative full implementations of Zero Trust**. No SMR digital twin, reactor safety model, containment mechanism, timing benchmark or deployed security system was evaluated. Do not present these outcomes as empirical attack-prevention, latency, availability or nuclear-safety evidence.

## Files
- `verify_policy.py` and `run_simulation.py`: complete runnable Python source.
- `truth_table_results.csv`: 16 exhaustive combinations.
- `scenario_verification.csv`: seven policy scenarios.
- `invalid_input_verification.csv`: four invalid-input tests.
- `verification_summary.json`: check totals.
- `request_decisions.csv`: all 9,000 decisions.
- `scenario_summary.csv`: scenario-level denied counts.
- `aggregate_summary.csv`: overall comparison.
- `simulation_metadata.json`: experimental scope.
- `Figure_Comparative_Synthetic_Policy_Outcomes.png`: high-resolution chart.

All generated results are reproducible from the source code.
