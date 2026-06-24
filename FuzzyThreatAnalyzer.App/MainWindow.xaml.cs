using System.Globalization;
using System.Windows;
using FuzzyThreatAnalyzer.Core.Engine;
using FuzzyThreatAnalyzer.Core.Fuzzy;
using FuzzyThreatAnalyzer.Core.Models;
using FuzzyThreatAnalyzer.Reporting;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;

namespace FuzzyThreatAnalyzer.App;

public partial class MainWindow : Window
{
    private readonly FuzzyThreatInferenceEngine engine = new();
    private ThreatAnalysisInput? lastInput;
    private ThreatAnalysisResult? lastResult;

    private readonly SolidColorPaint axisTextPaint = new(new SKColor(203, 213, 225));
    private readonly SolidColorPaint gridLinePaint = new(new SKColor(51, 65, 85));
    private readonly SolidColorPaint chartBackgroundPaint = new(new SKColor(11, 18, 32));
    private readonly SolidColorPaint chartBorderPaint = new(new SKColor(51, 65, 85));

    public MainWindow()
    {
        InitializeComponent();

        var defaultInput = new ThreatAnalysisInput
        {
            SampleName = "demo-malware",
            StaticScore = 70,
            DynamicScore = 85,
            NetworkScore = 65,
            PersistenceScore = 80,
            ObfuscationScore = 75,
            ReputationRiskScore = 70
        };

        UpdateInputScoreChart(defaultInput);
        UpdateMembershipFunctionChart();
        UpdateEmptyRuleChart();
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

        UpdateInputScoreChart(input);
        UpdateRuleStrengthChart(result);
        UpdateMembershipFunctionChart();

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

    private void UpdateInputScoreChart(ThreatAnalysisInput input)
    {
        var values = new[]
        {
            input.StaticScore,
            input.DynamicScore,
            input.NetworkScore,
            input.PersistenceScore,
            input.ObfuscationScore,
            input.ReputationRiskScore
        };

        InputScoreChart.DrawMarginFrame = CreateDarkFrame();

        InputScoreChart.Series = new ISeries[]
        {
            new ColumnSeries<double>
            {
                Name = "Input Score",
                Values = values,
                Fill = new SolidColorPaint(new SKColor(37, 99, 235)),
                Stroke = null,
                MaxBarWidth = 72
            }
        };

        InputScoreChart.XAxes = new[]
        {
            new Axis
            {
                Labels = new[]
                {
                    "Static",
                    "Dynamic",
                    "Network",
                    "Persistence",
                    "Obfuscation",
                    "Reputation"
                },
                LabelsRotation = 0,
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };

        InputScoreChart.YAxes = new[]
        {
            new Axis
            {
                MinLimit = 0,
                MaxLimit = 100,
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };
    }

    private void UpdateRuleStrengthChart(ThreatAnalysisResult result)
    {
        if (result.ActivatedRules.Count == 0)
        {
            UpdateEmptyRuleChart();
            return;
        }

        var rules = result.ActivatedRules.Take(6).ToList();

        RuleStrengthChart.DrawMarginFrame = CreateDarkFrame();

        RuleStrengthChart.Series = new ISeries[]
        {
            new ColumnSeries<double>
            {
                Name = "Rule Strength",
                Values = rules.Select(rule => rule.Strength).ToArray(),
                Fill = new SolidColorPaint(new SKColor(245, 158, 11)),
                Stroke = null,
                MaxBarWidth = 68
            }
        };

        RuleStrengthChart.XAxes = new[]
        {
            new Axis
            {
                Labels = rules
                    .Select((rule, index) => $"R{index + 1} • {rule.OutputSet}")
                    .ToArray(),
                LabelsRotation = 0,
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };

        RuleStrengthChart.YAxes = new[]
        {
            new Axis
            {
                MinLimit = 0,
                MaxLimit = 1,
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };
    }

    private void UpdateEmptyRuleChart()
    {
        RuleStrengthChart.DrawMarginFrame = CreateDarkFrame();

        RuleStrengthChart.Series = new ISeries[]
        {
            new ColumnSeries<double>
            {
                Name = "Rule Strength",
                Values = new double[] { 0 },
                Fill = new SolidColorPaint(new SKColor(245, 158, 11)),
                Stroke = null,
                MaxBarWidth = 68
            }
        };

        RuleStrengthChart.XAxes = new[]
        {
            new Axis
            {
                Labels = new[] { "No rules" },
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };

        RuleStrengthChart.YAxes = new[]
        {
            new Axis
            {
                MinLimit = 0,
                MaxLimit = 1,
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };
    }

    private void UpdateMembershipFunctionChart()
    {
        var low = new TriangularMembershipFunction("Low", 0, 0, 45);
        var medium = new TriangularMembershipFunction("Medium", 25, 50, 75);
        var high = new TriangularMembershipFunction("High", 55, 100, 100);

        MembershipFunctionChart.DrawMarginFrame = CreateDarkFrame();

        MembershipFunctionChart.Series = new ISeries[]
        {
            new LineSeries<double>
            {
                Name = "Low",
                Values = BuildMembershipValues(low),
                GeometrySize = 8,
                Stroke = new SolidColorPaint(new SKColor(56, 189, 248), 4),
                Fill = null
            },

            new LineSeries<double>
            {
                Name = "Medium",
                Values = BuildMembershipValues(medium),
                GeometrySize = 8,
                Stroke = new SolidColorPaint(new SKColor(34, 197, 94), 4),
                Fill = null
            },

            new LineSeries<double>
            {
                Name = "High",
                Values = BuildMembershipValues(high),
                GeometrySize = 8,
                Stroke = new SolidColorPaint(new SKColor(249, 115, 22), 4),
                Fill = null
            }
        };

        MembershipFunctionChart.XAxes = new[]
        {
            new Axis
            {
                Labels = Enumerable.Range(0, 11)
                    .Select(index => (index * 10).ToString(CultureInfo.InvariantCulture))
                    .ToArray(),
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };

        MembershipFunctionChart.YAxes = new[]
        {
            new Axis
            {
                MinLimit = 0,
                MaxLimit = 1,
                LabelsPaint = axisTextPaint,
                SeparatorsPaint = gridLinePaint,
                TextSize = 13
            }
        };
    }

    private DrawMarginFrame CreateDarkFrame()
    {
        return new DrawMarginFrame
        {
            Fill = chartBackgroundPaint,
            Stroke = chartBorderPaint
        };
    }

    private static double[] BuildMembershipValues(TriangularMembershipFunction function)
    {
        return Enumerable.Range(0, 11)
            .Select(index => function.GetMembership(index * 10))
            .ToArray();
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