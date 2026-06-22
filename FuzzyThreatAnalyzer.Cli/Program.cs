using System.Globalization;
using FuzzyThreatAnalyzer.Core.Engine;
using FuzzyThreatAnalyzer.Core.Models;

Console.WriteLine("FuzzyThreatAnalyzer");
Console.WriteLine("-------------------");

var input = new ThreatAnalysisInput
{
    SampleName = ReadText("Sample name"),
    StaticScore = ReadScore("Static score"),
    DynamicScore = ReadScore("Dynamic score"),
    NetworkScore = ReadScore("Network score"),
    PersistenceScore = ReadScore("Persistence score"),
    ObfuscationScore = ReadScore("Obfuscation score"),
    ReputationRiskScore = ReadScore("Reputation risk score")
};

var engine = new FuzzyThreatInferenceEngine();
var result = engine.Analyze(input);

Console.WriteLine();
Console.WriteLine("Analysis Result");
Console.WriteLine("-------------------");
Console.WriteLine($"Sample: {input.SampleName}");
Console.WriteLine($"Risk Score: {result.RiskScore:F2}/100");
Console.WriteLine($"Risk Level: {result.RiskLevel}");

Console.WriteLine();
Console.WriteLine("Input Memberships");
Console.WriteLine("-------------------");

foreach (var variable in result.InputMemberships)
{
    Console.WriteLine(variable.Key);

    foreach (var membership in variable.Value)
    {
        Console.WriteLine($"  {membership.Key}: {membership.Value:F2}");
    }
}

Console.WriteLine();
Console.WriteLine("Activated Rules");
Console.WriteLine("-------------------");

foreach (var rule in result.ActivatedRules)
{
    Console.WriteLine(rule.RuleName);
    Console.WriteLine($"  Output: {rule.OutputSet}");
    Console.WriteLine($"  Strength: {rule.Strength:F2}");
}

static string ReadText(string label)
{
    Console.Write($"{label}: ");
    var value = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(value))
    {
        return "Manual Sample";
    }

    return value.Trim();
}

static double ReadScore(string label)
{
    while (true)
    {
        Console.Write($"{label} (0-100): ");
        var text = Console.ReadLine()?.Replace(",", ".") ?? string.Empty;

        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
            && value >= 0
            && value <= 100)
        {
            return value;
        }

        Console.WriteLine("Please enter a number between 0 and 100.");
    }
}