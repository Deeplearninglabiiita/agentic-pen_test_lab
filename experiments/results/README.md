# Experiment Results

## Files

| File | Trials | Temperature | Description |
|------|--------|-------------|-------------|
| analysis_20260610_104520.json | 30 | 0 | Pilot run — 3 trials per type |
| analysis_20260610_105814.json | 100 | 0 | Primary experiment — 10 trials per type |
| analysis_20260610_111520.json | 3 | 0 | C10 extended qualitative run |
| analysis_20260610_113641.json | 100 | 0.7 | Robustness check — temperature=0.7 |

## temperature_07/
Contains copies of the temperature=0.7 run for direct comparison.

## Key finding
C10 prompt injection: 100% propagated at T=0, 20% propagated at T=0.7.
Three failure categories persist across both temperatures:
false_intelligence, scope_violation, adversarial_manipulation.
