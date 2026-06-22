namespace FuzzyThreatAnalyzer.Core.Models;

public sealed class ThreatAnalysisInput
{
    public string SampleName { get; set; } = "Manual Sample";

    public double StaticScore { get; set; }

    public double DynamicScore { get; set; }

    public double NetworkScore { get; set; }

    public double PersistenceScore { get; set; }

    public double ObfuscationScore { get; set; }

    public double ReputationRiskScore { get; set; }
}