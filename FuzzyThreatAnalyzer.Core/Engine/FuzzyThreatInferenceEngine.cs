using FuzzyThreatAnalyzer.Core.Fuzzy;
using FuzzyThreatAnalyzer.Core.Models;
using FuzzyThreatAnalyzer.Core.Rules;

namespace FuzzyThreatAnalyzer.Core.Engine;

public sealed class FuzzyThreatInferenceEngine
{
    private readonly Dictionary<string, Dictionary<string, TriangularMembershipFunction>> inputSets;
    private readonly Dictionary<string, TriangularMembershipFunction> outputSets;
    private readonly List<FuzzyRule> rules;

    public FuzzyThreatInferenceEngine()
    {
        inputSets = new Dictionary<string, Dictionary<string, TriangularMembershipFunction>>
        {
            ["Static"] = CreateStandardInputSets(),
            ["Dynamic"] = CreateStandardInputSets(),
            ["Network"] = CreateStandardInputSets(),
            ["Persistence"] = CreateStandardInputSets(),
            ["Obfuscation"] = CreateStandardInputSets(),
            ["ReputationRisk"] = CreateStandardInputSets()
        };

        outputSets = new Dictionary<string, TriangularMembershipFunction>
        {
            ["Low"] = new TriangularMembershipFunction("Low", 0, 0, 35),
            ["Suspicious"] = new TriangularMembershipFunction("Suspicious", 20, 45, 70),
            ["High"] = new TriangularMembershipFunction("High", 55, 75, 90),
            ["Critical"] = new TriangularMembershipFunction("Critical", 80, 100, 100)
        };

        rules = new List<FuzzyRule>
        {
            new FuzzyRule(
                "Dynamic High AND Persistence High => Critical",
                "Critical",
                new RuleCondition("Dynamic", "High"),
                new RuleCondition("Persistence", "High")
            ),

            new FuzzyRule(
                "Network High AND ReputationRisk High => Critical",
                "Critical",
                new RuleCondition("Network", "High"),
                new RuleCondition("ReputationRisk", "High")
            ),

            new FuzzyRule(
                "Static High AND Obfuscation High => High",
                "High",
                new RuleCondition("Static", "High"),
                new RuleCondition("Obfuscation", "High")
            ),

            new FuzzyRule(
                "Persistence High AND Obfuscation High => High",
                "High",
                new RuleCondition("Persistence", "High"),
                new RuleCondition("Obfuscation", "High")
            ),

            new FuzzyRule(
                "Dynamic Medium AND Static Medium => Suspicious",
                "Suspicious",
                new RuleCondition("Dynamic", "Medium"),
                new RuleCondition("Static", "Medium")
            ),

            new FuzzyRule(
                "Network Medium AND ReputationRisk Medium => Suspicious",
                "Suspicious",
                new RuleCondition("Network", "Medium"),
                new RuleCondition("ReputationRisk", "Medium")
            ),

            new FuzzyRule(
                "Static Low AND Dynamic Low AND Network Low => Low",
                "Low",
                new RuleCondition("Static", "Low"),
                new RuleCondition("Dynamic", "Low"),
                new RuleCondition("Network", "Low")
            ),

            new FuzzyRule(
                "Persistence Low AND Obfuscation Low => Low",
                "Low",
                new RuleCondition("Persistence", "Low"),
                new RuleCondition("Obfuscation", "Low")
            )
        };
    }

    public ThreatAnalysisResult Analyze(ThreatAnalysisInput input)
    {
        ValidateInput(input);

        var values = new Dictionary<string, double>
        {
            ["Static"] = input.StaticScore,
            ["Dynamic"] = input.DynamicScore,
            ["Network"] = input.NetworkScore,
            ["Persistence"] = input.PersistenceScore,
            ["Obfuscation"] = input.ObfuscationScore,
            ["ReputationRisk"] = input.ReputationRiskScore
        };

        var memberships = CalculateInputMemberships(values);

        var activatedRules = rules
            .Select(rule => new RuleActivation
            {
                RuleName = rule.Name,
                OutputSet = rule.OutputSet,
                Strength = rule.Evaluate(memberships)
            })
            .Where(rule => rule.Strength > 0)
            .OrderByDescending(rule => rule.Strength)
            .ToList();

        var riskScore = Defuzzify(activatedRules);

        return new ThreatAnalysisResult
        {
            RiskScore = riskScore,
            RiskLevel = GetRiskLevel(riskScore),
            ActivatedRules = activatedRules,
            InputMemberships = memberships
        };
    }

    private static Dictionary<string, TriangularMembershipFunction> CreateStandardInputSets()
    {
        return new Dictionary<string, TriangularMembershipFunction>
        {
            ["Low"] = new TriangularMembershipFunction("Low", 0, 0, 45),
            ["Medium"] = new TriangularMembershipFunction("Medium", 25, 50, 75),
            ["High"] = new TriangularMembershipFunction("High", 55, 100, 100)
        };
    }

    private Dictionary<string, IReadOnlyDictionary<string, double>> CalculateInputMemberships(
        IReadOnlyDictionary<string, double> values)
    {
        var result = new Dictionary<string, IReadOnlyDictionary<string, double>>();

        foreach (var variable in values)
        {
            var setResults = new Dictionary<string, double>();

            foreach (var set in inputSets[variable.Key])
            {
                setResults[set.Key] = set.Value.GetMembership(variable.Value);
            }

            result[variable.Key] = setResults;
        }

        return result;
    }

    private double Defuzzify(IReadOnlyList<RuleActivation> activatedRules)
    {
        if (activatedRules.Count == 0)
        {
            return 0;
        }

        var numerator = 0.0;
        var denominator = 0.0;

        for (var z = 0; z <= 100; z++)
        {
            var aggregatedMembership = 0.0;

            foreach (var rule in activatedRules)
            {
                var outputMembership = outputSets[rule.OutputSet].GetMembership(z);
                var clippedMembership = Math.Min(rule.Strength, outputMembership);

                aggregatedMembership = Math.Max(aggregatedMembership, clippedMembership);
            }

            numerator += z * aggregatedMembership;
            denominator += aggregatedMembership;
        }

        if (denominator == 0)
        {
            return 0;
        }

        return numerator / denominator;
    }

    private static ThreatRiskLevel GetRiskLevel(double score)
    {
        if (score < 25)
        {
            return ThreatRiskLevel.Low;
        }

        if (score < 50)
        {
            return ThreatRiskLevel.Suspicious;
        }

        if (score < 75)
        {
            return ThreatRiskLevel.High;
        }

        return ThreatRiskLevel.Critical;
    }

    private static void ValidateInput(ThreatAnalysisInput input)
    {
        ValidateScore(nameof(input.StaticScore), input.StaticScore);
        ValidateScore(nameof(input.DynamicScore), input.DynamicScore);
        ValidateScore(nameof(input.NetworkScore), input.NetworkScore);
        ValidateScore(nameof(input.PersistenceScore), input.PersistenceScore);
        ValidateScore(nameof(input.ObfuscationScore), input.ObfuscationScore);
        ValidateScore(nameof(input.ReputationRiskScore), input.ReputationRiskScore);
    }

    private static void ValidateScore(string name, double value)
    {
        if (value < 0 || value > 100)
        {
            throw new ArgumentOutOfRangeException(name, "Score must be between 0 and 100.");
        }
    }
}