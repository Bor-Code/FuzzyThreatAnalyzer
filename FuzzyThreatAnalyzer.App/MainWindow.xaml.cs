using System.Globalization;
using System.Windows;
using FuzzyThreatAnalyzer.Core.Engine;
using FuzzyThreatAnalyzer.Core.Models;
using FuzzyThreatAnalyzer.Reporting;

namespace FuzzyThreatAnalyzer.App;

public partial class MainWindow : Window
{
    private readonly FuzzyThreatInferenceEngine engine = new();
    private ThreatAnalysisInput? lastInput;
    private ThreatAnalysisResult? lastResult;

    public MainWindow()
    {
        InitializeComponent();
        LoadDefaultMetricRows();
    }

    private void AnalyzeButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var input = ReadInput();
            var result = engine.Analyze(input);

            lastInput = input;
            lastResult = result;

            UpdateDashboard(input, result);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Analiz hatası",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ExportReportButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (lastInput is null || lastResult is null)
            {
                var input = ReadInput();
                var result = engine.Analyze(input);

                lastInput = input;
                lastResult = result;

                UpdateDashboard(input, result);
            }

            var reportsDirectory = System.IO.Path.Combine(AppContext.BaseDirectory, "reports");
            var exporter = new ThreatReportExporter();

            exporter.Export(reportsDirectory, lastInput, lastResult);

            MessageBox.Show(
                $"Raporlar oluşturuldu:\n\n{reportsDirectory}",
                "Rapor dışa aktarıldı",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Rapor hatası",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private ThreatAnalysisInput ReadInput()
    {
        return new ThreatAnalysisInput
        {
            SampleName = string.IsNullOrWhiteSpace(SampleNameTextBox.Text)
                ? "Manual Sample"
                : SampleNameTextBox.Text.Trim(),

            StaticScore = ReadScore(StaticScoreTextBox.Text, "Static score"),
            DynamicScore = ReadScore(DynamicScoreTextBox.Text, "Dynamic score"),
            NetworkScore = ReadScore(NetworkScoreTextBox.Text, "Network score"),
            PersistenceScore = ReadScore(PersistenceScoreTextBox.Text, "Persistence score"),
            ObfuscationScore = ReadScore(ObfuscationScoreTextBox.Text, "Obfuscation score"),
            ReputationRiskScore = ReadScore(ReputationRiskScoreTextBox.Text, "Reputation risk score")
        };
    }

    private static double ReadScore(string text, string fieldName)
    {
        var normalized = text.Replace(",", ".");

        if (!double.TryParse(normalized, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
        {
            throw new InvalidOperationException($"{fieldName} sayı olmalıdır.");
        }

        if (value < 0 || value > 100)
        {
            throw new InvalidOperationException($"{fieldName} 0 ile 100 arasında olmalıdır.");
        }

        return value;
    }

    private void UpdateDashboard(ThreatAnalysisInput input, ThreatAnalysisResult result)
    {
        RiskScoreTextBlock.Text = $"{result.RiskScore:F2}/100";
        RiskLevelTextBlock.Text = result.RiskLevel.ToString();
        RiskProgressBar.Value = result.RiskScore;

        TopExplanationTextBlock.Text = BuildExplanation(result);

        MetricBarsItemsControl.ItemsSource = CreateMetricRows(input);
        MembershipsGrid.ItemsSource = CreateMembershipRows(result);
        RulesGrid.ItemsSource = CreateRuleRows(result);
    }

    private static string BuildExplanation(ThreatAnalysisResult result)
    {
        var strongestRule = result.ActivatedRules.FirstOrDefault();

        if (strongestRule is null)
        {
            return "Hiçbir kural aktifleşmedi. Risk skoru düşük kabul edildi.";
        }

        return $"En güçlü kural: {strongestRule.RuleName} | Güç: {strongestRule.Strength:F2}";
    }

    private void LoadDefaultMetricRows()
    {
        var input = new ThreatAnalysisInput
        {
            SampleName = "demo-malware",
            StaticScore = 70,
            DynamicScore = 85,
            NetworkScore = 65,
            PersistenceScore = 80,
            ObfuscationScore = 75,
            ReputationRiskScore = 70
        };

        MetricBarsItemsControl.ItemsSource = CreateMetricRows(input);
    }

    private static IReadOnlyList<MetricRow> CreateMetricRows(ThreatAnalysisInput input)
    {
        return new List<MetricRow>
        {
            new("Static", input.StaticScore),
            new("Dynamic", input.DynamicScore),
            new("Network", input.NetworkScore),
            new("Persistence", input.PersistenceScore),
            new("Obfuscation", input.ObfuscationScore),
            new("ReputationRisk", input.ReputationRiskScore)
        };
    }

    private static IReadOnlyList<MembershipRow> CreateMembershipRows(ThreatAnalysisResult result)
    {
        return result.InputMemberships
            .Select(item => new MembershipRow(
                item.Key,
                GetMembership(item.Value, "Low"),
                GetMembership(item.Value, "Medium"),
                GetMembership(item.Value, "High")))
            .ToList();
    }

    private static IReadOnlyList<RuleRow> CreateRuleRows(ThreatAnalysisResult result)
    {
        return result.ActivatedRules
            .Select(rule => new RuleRow(
                rule.RuleName,
                rule.OutputSet,
                rule.Strength))
            .ToList();
    }

    private static double GetMembership(IReadOnlyDictionary<string, double> memberships, string setName)
    {
        if (memberships.TryGetValue(setName, out var value))
        {
            return value;
        }

        return 0;
    }
}

public sealed record MetricRow(string Name, double Score)
{
    public string ScoreText => $"{Score:F0}/100";
}

public sealed record MembershipRow(string Metric, double Low, double Medium, double High)
{
    public string LowText => Low.ToString("F2", CultureInfo.InvariantCulture);

    public string MediumText => Medium.ToString("F2", CultureInfo.InvariantCulture);

    public string HighText => High.ToString("F2", CultureInfo.InvariantCulture);
}

public sealed record RuleRow(string RuleName, string OutputSet, double Strength)
{
    public string StrengthText => Strength.ToString("F2", CultureInfo.InvariantCulture);
}