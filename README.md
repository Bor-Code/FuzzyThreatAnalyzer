\# FuzzyThreatAnalyzer



FuzzyThreatAnalyzer is an explainable threat analysis tool that uses fuzzy logic to score cybersecurity risk indicators.



Instead of classifying a sample as only `safe` or `malicious`, the tool calculates how risky the sample is by evaluating multiple uncertain indicators such as static analysis, dynamic behavior, network activity, persistence, obfuscation, and reputation risk.



\## Why fuzzy logic?



Cybersecurity decisions are often uncertain.



A file may not be completely safe or completely malicious. For example:



\* A file may have medium static indicators.

\* It may show suspicious dynamic behavior.

\* It may contact unknown network destinations.

\* It may use some obfuscation techniques.



Traditional binary logic usually gives sharp decisions. Fuzzy logic allows the system to work with degrees of membership such as:



```text

Low: 0.00

Medium: 0.60

High: 0.11

```



This makes the threat analysis more explainable and closer to real-world decision making.



\## Features



\* Fuzzy logic based threat scoring

\* Mamdani-style inference approach

\* Static, dynamic, network, persistence, obfuscation, and reputation risk inputs

\* Low, Suspicious, High, and Critical risk levels

\* Activated fuzzy rule explanation

\* Interactive CLI input mode

\* JSON sample input support

\* Markdown threat report export

\* CSV metrics export



\## Project Structure



```text

FuzzyThreatAnalyzer/

├── FuzzyThreatAnalyzer.Core/

│   ├── Engine/

│   ├── Fuzzy/

│   ├── Models/

│   └── Rules/

│

├── FuzzyThreatAnalyzer.Cli/

│   └── Program.cs

│

├── FuzzyThreatAnalyzer.Reporting/

│   └── ThreatReportExporter.cs

│

├── samples/

│   ├── low-risk-sample.json

│   ├── suspicious-sample.json

│   └── critical-sample.json

│

└── README.md

```



\## Input Metrics



Each input metric is scored between `0` and `100`.



| Metric                | Description                                                       |

| --------------------- | ----------------------------------------------------------------- |

| Static Score          | Suspicious indicators found during static analysis                |

| Dynamic Score         | Runtime behavior such as process, registry, or file activity      |

| Network Score         | Network activity, suspicious destinations, or unusual connections |

| Persistence Score     | Startup, service, scheduled task, or other persistence behavior   |

| Obfuscation Score     | Packing, encryption, anti-debug, or code hiding behavior          |

| Reputation Risk Score | Risk based on hash, IP, domain, or external reputation signals    |



\## Risk Levels



| Risk Score | Risk Level |

| ---------: | ---------- |

|     0 - 24 | Low        |

|    25 - 49 | Suspicious |

|    50 - 74 | High       |

|   75 - 100 | Critical   |



\## Example Fuzzy Rules



```text

IF Dynamic is High AND Persistence is High THEN Threat is Critical



IF Network is High AND ReputationRisk is High THEN Threat is Critical



IF Static is High AND Obfuscation is High THEN Threat is High



IF Dynamic is Medium AND Static is Medium THEN Threat is Suspicious



IF Static is Low AND Dynamic is Low AND Network is Low THEN Threat is Low

```



\## How to Run



\### Run with interactive input



```powershell

dotnet run --project .\\FuzzyThreatAnalyzer.Cli\\FuzzyThreatAnalyzer.Cli.csproj

```



The CLI will ask for each score manually:



```text

Sample name:

Static score (0-100):

Dynamic score (0-100):

Network score (0-100):

Persistence score (0-100):

Obfuscation score (0-100):

Reputation risk score (0-100):

```



\### Run with a JSON sample



```powershell

dotnet run --project .\\FuzzyThreatAnalyzer.Cli\\FuzzyThreatAnalyzer.Cli.csproj -- .\\samples\\critical-sample.json

```



\## Sample JSON Input



```json

{

&#x20; "sampleName": "critical-sample",

&#x20; "staticScore": 85,

&#x20; "dynamicScore": 90,

&#x20; "networkScore": 80,

&#x20; "persistenceScore": 88,

&#x20; "obfuscationScore": 75,

&#x20; "reputationRiskScore": 90

}

```



\## Example Output



```text

FuzzyThreatAnalyzer

\-------------------



Analysis Result

\-------------------

Sample: critical-sample

Risk Score: 82.45/100

Risk Level: Critical



Input Memberships

\-------------------

Static

&#x20; Low: 0.00

&#x20; Medium: 0.00

&#x20; High: 0.67



Dynamic

&#x20; Low: 0.00

&#x20; Medium: 0.00

&#x20; High: 0.78



Activated Rules

\-------------------

Network High AND ReputationRisk High => Critical

&#x20; Output: Critical

&#x20; Strength: 0.56



Dynamic High AND Persistence High => Critical

&#x20; Output: Critical

&#x20; Strength: 0.73

```



\## Report Export



After each analysis, the tool generates:



```text

reports/threat-report.md

reports/threat-metrics.csv

```



The Markdown report contains:



\* Summary

\* Input scores

\* Membership degrees

\* Activated fuzzy rules



The CSV export contains structured metrics that can be used for charts or future dashboard features.



\## Architecture



The project is separated into three main layers.



| Project                       | Responsibility                                            |

| ----------------------------- | --------------------------------------------------------- |

| FuzzyThreatAnalyzer.Core      | Fuzzy sets, membership functions, rules, inference engine |

| FuzzyThreatAnalyzer.Cli       | Command-line user interaction and execution flow          |

| FuzzyThreatAnalyzer.Reporting | Markdown and CSV report generation                        |



\## Roadmap



\* WPF dashboard interface

\* Risk score gauge

\* Membership function charts

\* Rule activation chart

\* HTML report export

\* PDF report export

\* Configurable fuzzy rule files

\* Real static analysis integration

\* Real dynamic behavior input integration



\## Disclaimer



This project is designed for educational and portfolio purposes. It does not replace professional malware analysis tools or threat intelligence platforms.



