namespace FuzzyThreatAnalyzer.Core.Models;

public sealed class RuleActivation
{
    public string RuleName { get; init; } = string.Empty;

    public string OutputSet { get; init; } = string.Empty;

    public double Strength { get; init; }
}