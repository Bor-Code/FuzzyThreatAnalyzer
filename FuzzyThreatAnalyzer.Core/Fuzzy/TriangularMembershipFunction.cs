namespace FuzzyThreatAnalyzer.Core.Fuzzy;

public sealed class TriangularMembershipFunction
{
    public TriangularMembershipFunction(string name, double a, double b, double c)
    {
        Name = name;
        A = a;
        B = b;
        C = c;
    }

    public string Name { get; }

    public double A { get; }

    public double B { get; }

    public double C { get; }

    public double GetMembership(double x)
    {
        if (x <= A)
        {
            return A == B && x == A ? 1.0 : 0.0;
        }

        if (x >= C)
        {
            return B == C && x == C ? 1.0 : 0.0;
        }

        if (x == B)
        {
            return 1.0;
        }

        if (x < B)
        {
            return (x - A) / (B - A);
        }

        return (C - x) / (C - B);
    }
}