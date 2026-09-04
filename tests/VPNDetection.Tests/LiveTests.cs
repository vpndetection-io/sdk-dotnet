using Xunit;

namespace VPNDetection.Tests;

// Hits the real API, so it is opt-in: VPNDETECTION_LIVE=1 dotnet test.
//
// CI leaves it off. A test suite that spends the keyless daily allowance on every pull request
// eventually fails for reasons that have nothing to do with the change under review.
public class LiveTests
{
    [Fact]
    public async Task TheFreeTierAnswersIsVpnAndWithholdsEverythingElse()
    {
        Assert.SkipUnless(
            Environment.GetEnvironmentVariable("VPNDETECTION_LIVE") == "1",
            "set VPNDETECTION_LIVE=1 to spend the keyless daily allowance");

        using var client = new VpnDetectionClient();

        var vpn = await client.LookupAsync("45.83.91.1");
        var notVpn = await client.LookupAsync("1.1.1.1");
        var bogon = await client.LookupAsync("192.168.1.1");

        Console.WriteLine($"45.83.91.1  -> isVpn={vpn.IsVpn} isHosting={Show(vpn.IsHosting)} "
            + $"isBogon={vpn.IsBogon} raw={Corpus.AsWire(vpn.Raw)}");
        Console.WriteLine($"1.1.1.1     -> isVpn={notVpn.IsVpn} isHosting={Show(notVpn.IsHosting)} "
            + $"isHosting ?? false={notVpn.IsHosting ?? false} raw={Corpus.AsWire(notVpn.Raw)}");
        Console.WriteLine($"192.168.1.1 -> isVpn={bogon.IsVpn} isBogon={bogon.IsBogon} "
            + $"raw={Corpus.AsWire(bogon.Raw)}");

        Assert.True(vpn.IsVpn, "45.83.91.1 is VPN infrastructure");
        Assert.False(notVpn.IsVpn, "1.1.1.1 is not");
        // Absent, not false: the hosting flag is a paid member and this call carries no key.
        Assert.Null(notVpn.IsHosting);
        Assert.False(notVpn.IsHosting ?? false);

        Assert.True(bogon.IsBogon);
        Assert.Equal("192.168.1.1", bogon.Ip);
    }

    private static string Show(bool? flag) => flag?.ToString() ?? "absent";
}
