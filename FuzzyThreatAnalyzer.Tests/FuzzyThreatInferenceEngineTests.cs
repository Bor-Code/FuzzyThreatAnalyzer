using FuzzyThreatAnalyzer.Core.Engine;
using FuzzyThreatAnalyzer.Core.Models;

namespace FuzzyThreatAnalyzer.Tests;

public sealed class FuzzyThreatInferenceEngineTests
{
    [Fact]
    public void Analyze_ReturnsLowRisk_ForLowInputScores()
    {
        var engine = new FuzzyThreatInferenceEngine();

        var input = new ThreatAnalysisInput
        {
            SampleName = "low-risk-test",
            StaticScore = 15,
            DynamicScore = 10,
            NetworkScore = 12,
            PersistenceScore = 8,
            ObfuscationScore = 5,
            ReputationRiskScore = 10
        };

        var result = engine.Analyze(input);

        Assert.Equal(ThreatRiskLevel.Low, result.RiskLevel);
        Assert.InRange(result.RiskScore, 0, 40);
        Assert.NotEmpty(result.ActivatedRules);
    }

    [Fact]
    public void Analyze_ReturnsCriticalRisk_ForCriticalInputScores()
    {
        var engine = new FuzzyThreatInferenceEngine();

        var input = new ThreatAnalysisInput
        {
            SampleName = "critical-risk-test",
            StaticScore = 85,
            DynamicScore = 90,
            NetworkScore = 80,
            PersistenceScore = 88,
            ObfuscationScore = 75,
            ReputationRiskScore = 90
        };

        var result = engine.Analyze(input);

        Assert.Equal(ThreatRiskLevel.Critical, result.RiskLevel);
        Assert.InRange(result.RiskScore, 75, 100);
        Assert.Contains(result.ActivatedRules, rule => rule.OutputSet == "Critical");
    }

    [Fact]
    public void Analyze_ReturnsSuspiciousRisk_ForMediumStaticAndDynamicScores()
    {
        var engine = new FuzzyThreatInferenceEngine();

        var input = new ThreatAnalysisInput
        {
            SampleName = "suspicious-risk-test",
            StaticScore = 50,
            DynamicScore = 60,
            NetworkScore = 40,
            PersistenceScore = 30,
            ObfuscationScore = 20,
            ReputationRiskScore = 10
        };

        var result = engine.Analyze(input);

        Assert.Equal(ThreatRiskLevel.Suspicious, result.RiskLevel);
        Assert.Contains(result.ActivatedRules, rule => rule.OutputSet == "Suspicious");
    }

    [Fact]
    public void Analyze_ThrowsException_WhenScoreIsOutOfRange()
    {
        var engine = new FuzzyThreatInferenceEngine();

        var input = new ThreatAnalysisInput
        {
            SampleName = "invalid-test",
            StaticScore = 150,
            DynamicScore = 10,
            NetworkScore = 10,
            PersistenceScore = 10,
            ObfuscationScore = 10,
            ReputationRiskScore = 10
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => engine.Analyze(input));
    }
}