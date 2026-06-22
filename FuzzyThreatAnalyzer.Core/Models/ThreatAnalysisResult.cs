namespace FuzzyThreatAnalyzer.Core.Models;

public sealed class ThreatAnalysisResult
{
    public double RiskScore { get; init; }

    public ThreatRiskLevel RiskLevel { get; init; }

    public IReadOnlyList<RuleActivation> ActivatedRules { get; init; } = Array.Empty<RuleActivation>();

    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, double>> InputMemberships { get; init; }
        = new Dictionary<string, IReadOnlyDictionary<string, double>>();
}