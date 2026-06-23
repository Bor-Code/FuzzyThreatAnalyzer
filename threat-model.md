# Threat Model

This document explains the threat scoring model used by FuzzyThreatAnalyzer.

The purpose of the model is not to decide whether a sample is strictly safe or malicious. Instead, it estimates the degree of threat by combining multiple uncertain cybersecurity indicators with fuzzy logic.

## Scoring Philosophy

Traditional binary logic usually works with sharp decisions:

```text
Safe = 0
Malicious = 1
```

However, real-world threat analysis is not always binary. A sample may be partially suspicious, partially risky, or strongly malicious depending on different indicators.

FuzzyThreatAnalyzer uses fuzzy membership degrees between `0` and `1`.

Example:

```text
Dynamic Score: 60

Low: 0.00
Medium: 0.60
High: 0.11
```

This means the behavior is mostly medium but slightly high.

## Input Metrics

Each input metric is scored between `0` and `100`.

| Metric                | Description                                   | Low Example                      | High Example                                |
| --------------------- | --------------------------------------------- | -------------------------------- | ------------------------------------------- |
| Static Score          | Indicators found without executing the sample | Few suspicious strings           | Packer, imports, suspicious strings         |
| Dynamic Score         | Runtime behavior                              | No suspicious runtime action     | Process injection, file drop, registry edit |
| Network Score         | Network activity                              | No connection or trusted traffic | Suspicious IP, unknown domain, beaconing    |
| Persistence Score     | Attempts to remain on the system              | No startup behavior              | Service, scheduled task, registry run key   |
| Obfuscation Score     | Code hiding techniques                        | Plain readable binary/script     | Packed, encrypted, anti-debug behavior      |
| Reputation Risk Score | External reputation of hash, IP, or domain    | Known trusted object             | Unknown or known malicious indicator        |

## Input Fuzzy Sets

For each input metric, the system uses three fuzzy sets:

| Set    | Meaning                                        |
| ------ | ---------------------------------------------- |
| Low    | The indicator is weak or not important         |
| Medium | The indicator is suspicious but not conclusive |
| High   | The indicator strongly increases threat risk   |

Current triangular membership functions:

```text
Low    = (0, 0, 45)
Medium = (25, 50, 75)
High   = (55, 100, 100)
```

## Output Risk Sets

The output risk score is also represented with fuzzy sets.

| Output Set | Meaning                                 |
| ---------- | --------------------------------------- |
| Low        | The sample looks mostly safe            |
| Suspicious | The sample requires attention           |
| High       | The sample has strong threat indicators |
| Critical   | The sample is likely dangerous          |

Current output membership functions:

```text
Low        = (0, 0, 35)
Suspicious = (20, 45, 70)
High       = (55, 75, 90)
Critical   = (80, 100, 100)
```

## Rule Base

The current rule base is intentionally small and explainable.

### Critical Rules

```text
IF Dynamic is High AND Persistence is High THEN Threat is Critical
```

Reason: A sample that behaves suspiciously at runtime and tries to remain on the system is a strong threat candidate.

```text
IF Network is High AND ReputationRisk is High THEN Threat is Critical
```

Reason: Suspicious network behavior combined with bad or unknown reputation is highly risky.

### High Rules

```text
IF Static is High AND Obfuscation is High THEN Threat is High
```

Reason: Static indicators combined with obfuscation may suggest an attempt to hide malicious behavior.

```text
IF Persistence is High AND Obfuscation is High THEN Threat is High
```

Reason: A sample that hides itself and tries to persist is dangerous even if not all indicators are critical.

### Suspicious Rules

```text
IF Dynamic is Medium AND Static is Medium THEN Threat is Suspicious
```

Reason: Medium static and dynamic indicators are not enough for a critical decision, but they deserve attention.

```text
IF Network is Medium AND ReputationRisk is Medium THEN Threat is Suspicious
```

Reason: Moderate network and reputation indicators can represent suspicious behavior.

### Low Rules

```text
IF Static is Low AND Dynamic is Low AND Network is Low THEN Threat is Low
```

Reason: If the main indicators are weak, the sample is likely low risk.

```text
IF Persistence is Low AND Obfuscation is Low THEN Threat is Low
```

Reason: Lack of persistence and obfuscation reduces the overall risk.

## Inference Method

The current implementation follows a Mamdani-style fuzzy inference approach.

The process is:

```text
1. Read input scores
2. Convert crisp scores into fuzzy memberships
3. Evaluate fuzzy rules
4. Aggregate rule outputs
5. Defuzzify the result into a single risk score
```

## AND Operation

For AND conditions, the system uses the minimum value.

Example:

```text
Dynamic High = 0.78
Persistence High = 0.73

Rule strength = min(0.78, 0.73)
Rule strength = 0.73
```

## Output Aggregation

When multiple rules produce the same or different output sets, the system aggregates them using the maximum value.

Example:

```text
Critical from rule 1 = 0.73
Critical from rule 2 = 0.56

Aggregated Critical = max(0.73, 0.56)
Aggregated Critical = 0.73
```

## Defuzzification

After rule evaluation and aggregation, the fuzzy output must be converted into a single number.

FuzzyThreatAnalyzer calculates a final risk score between `0` and `100`.

Example:

```text
Risk Score: 82.45/100
Risk Level: Critical
```

## Limitations

This model is educational and rule-based. It does not currently perform real malware analysis by itself.

Current limitations:

* Input scores are manually entered or loaded from JSON.
* Static and dynamic analysis are not yet automated.
* The rule base is small.
* Membership functions are hardcoded.
* No external threat intelligence API is connected yet.

## Future Improvements

Planned improvements:

* Configurable membership functions
* Configurable rule files
* Real static analysis feature extraction
* Real dynamic sandbox behavior input
* VirusTotal or similar reputation integration
* WPF dashboard with charts
* PDF and HTML report export
