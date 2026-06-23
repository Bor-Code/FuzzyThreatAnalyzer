using FuzzyThreatAnalyzer.Core.Fuzzy;

namespace FuzzyThreatAnalyzer.Tests;

public sealed class TriangularMembershipFunctionTests
{
    [Fact]
    public void GetMembership_ReturnsOneAtPeak()
    {
        var function = new TriangularMembershipFunction("Medium", 25, 50, 75);

        var result = function.GetMembership(50);

        Assert.Equal(1.0, result);
    }

    [Fact]
    public void GetMembership_ReturnsZeroOutsideRange()
    {
        var function = new TriangularMembershipFunction("Medium", 25, 50, 75);

        var leftResult = function.GetMembership(10);
        var rightResult = function.GetMembership(90);

        Assert.Equal(0.0, leftResult);
        Assert.Equal(0.0, rightResult);
    }

    [Fact]
    public void GetMembership_ReturnsPartialValueOnRisingEdge()
    {
        var function = new TriangularMembershipFunction("Medium", 25, 50, 75);

        var result = function.GetMembership(37.5);

        Assert.Equal(0.5, result);
    }

    [Fact]
    public void GetMembership_ReturnsPartialValueOnFallingEdge()
    {
        var function = new TriangularMembershipFunction("Medium", 25, 50, 75);

        var result = function.GetMembership(62.5);

        Assert.Equal(0.5, result);
    }
}