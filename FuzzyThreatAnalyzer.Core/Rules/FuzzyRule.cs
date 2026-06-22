namespace FuzzyThreatAnalyzer.Core.Rules;

public sealed class FuzzyRule
{
    public FuzzyRule(string name, string outputSet, params RuleCondition[] conditions)
    {
        Name = name;
        OutputSet = outputSet;
        Conditions = conditions;
    }

    public string Name { get; }

    public string OutputSet { get; }

    public IReadOnlyList<RuleCondition> Conditions { get; }

    public double Evaluate(IReadOnlyDictionary<string, IReadOnlyDictionary<string, double>> memberships)
    {
        var strength = 1.0;

        foreach (var condition in Conditions)
        {
            var value = memberships[condition.VariableName][condition.SetName];
            strength = Math.Min(strength, value);
        }

        return strength;
    }
}