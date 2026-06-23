using System.Globalization;
using System.Text;
using FuzzyThreatAnalyzer.Core.Models;

namespace FuzzyThreatAnalyzer.Reporting;

public sealed class ThreatReportExporter
{
    public void Export(string outputDirectory, ThreatAnalysisInput input, ThreatAnalysisResult result)
    {
        if (string.IsNullOrWhiteSpace(outputDirectory))
        {
            throw new ArgumentException("Output directory cannot be empty.", nameof(outputDirectory));
        }

        Directory.CreateDirectory(outputDirectory);

        var markdownPath = Path.Combine(outputDirectory, "threat-report.md");
        var csvPath = Path.Combine(outputDirectory, "threat-metrics.csv");

        File.WriteAllText(markdownPath, BuildMarkdown(input, result), Encoding.UTF8);
        File.WriteAllText(csvPath, BuildCsv(input, result), Encoding.UTF8);
    }

    private static string BuildMarkdown(ThreatAnalysisInput input, ThreatAnalysisResult result)
    {
        var builder = new StringBuilder();

        builder.AppendLine("# Fuzzy Threat Analysis Report");
        builder.AppendLine();
        builder.AppendLine("## Summary");
        builder.AppendLine();
        builder.AppendLine("| Field | Value |");
        builder.AppendLine("|---|---|");
        builder.AppendLine($"| Sample | {EscapeMarkdown(input.SampleName)} |");
        builder.AppendLine($"| Risk score | {Format(result.RiskScore)}/100 |");
        builder.AppendLine($"| Risk level | {result.RiskLevel} |");
        builder.AppendLine();

        builder.AppendLine("## Input Scores");
        builder.AppendLine();
        builder.AppendLine("| Metric | Score |");
        builder.AppendLine("|---|---:|");

        foreach (var item in CreateInputValues(input))
        {
            builder.AppendLine($"| {item.Key} | {Format(item.Value)} |");
        }

        builder.AppendLine();
        builder.AppendLine("## Input Memberships");
        builder.AppendLine();
        builder.AppendLine("| Metric | Low | Medium | High |");
        builder.AppendLine("|---|---:|---:|---:|");

        foreach (var item in result.InputMemberships)
        {
            var low = GetMembershipValue(item.Value, "Low");
            var medium = GetMembershipValue(item.Value, "Medium");
            var high = GetMembershipValue(item.Value, "High");

            builder.AppendLine($"| {item.Key} | {Format(low)} | {Format(medium)} | {Format(high)} |");
        }

        builder.AppendLine();
        builder.AppendLine("## Activated Rules");
        builder.AppendLine();

        if (result.ActivatedRules.Count == 0)
        {
            builder.AppendLine("No fuzzy rules were activated.");
        }
        else
        {
            builder.AppendLine("| Rule | Output | Strength |");
            builder.AppendLine("|---|---|---:|");

            foreach (var rule in result.ActivatedRules)
            {
                builder.AppendLine($"| {EscapeMarkdown(rule.RuleName)} | {rule.OutputSet} | {Format(rule.Strength)} |");
            }
        }

        return builder.ToString();
    }

    private static string BuildCsv(ThreatAnalysisInput input, ThreatAnalysisResult result)
    {
        var builder = new StringBuilder();

        builder.AppendLine(Csv("Section", "Name", "Set", "Value"));

        builder.AppendLine(Csv("Result", "RiskScore", string.Empty, Format(result.RiskScore)));
        builder.AppendLine(Csv("Result", "RiskLevel", string.Empty, result.RiskLevel.ToString()));

        foreach (var item in CreateInputValues(input))
        {
            builder.AppendLine(Csv("Input", item.Key, "Score", Format(item.Value)));
        }

        foreach (var variable in result.InputMemberships)
        {
            foreach (var membership in variable.Value)
            {
                builder.AppendLine(Csv("Membership", variable.Key, membership.Key, Format(membership.Value)));
            }
        }

        foreach (var rule in result.ActivatedRules)
        {
            builder.AppendLine(Csv("Rule", rule.RuleName, rule.OutputSet, Format(rule.Strength)));
        }

        return builder.ToString();
    }

    private static IReadOnlyDictionary<string, double> CreateInputValues(ThreatAnalysisInput input)
    {
        return new Dictionary<string, double>
        {
            ["Static"] = input.StaticScore,
            ["Dynamic"] = input.DynamicScore,
            ["Network"] = input.NetworkScore,
            ["Persistence"] = input.PersistenceScore,
            ["Obfuscation"] = input.ObfuscationScore,
            ["ReputationRisk"] = input.ReputationRiskScore
        };
    }

    private static double GetMembershipValue(IReadOnlyDictionary<string, double> memberships, string setName)
    {
        if (memberships.TryGetValue(setName, out var value))
        {
            return value;
        }

        return 0;
    }

    private static string Format(double value)
    {
        return value.ToString("F2", CultureInfo.InvariantCulture);
    }

    private static string EscapeMarkdown(string value)
    {
        return value.Replace("|", "\\|");
    }

    private static string Csv(params string[] values)
    {
        return string.Join(",", values.Select(EscapeCsv));
    }

    private static string EscapeCsv(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        return value;
    }
}