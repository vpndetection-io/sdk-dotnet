using System.Text.Json;

using Xunit;

namespace VPNDetection.Integration;

// The published package looking addresses up against the staging API.
//
// Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each one serving a
// superset of the tier below it, so a pricing change stays a pricing change instead of arriving as
// a red SDK build. What a served answer must satisfy on every tier: ip and is_vpn always; a present
// flag is a real boolean; a field a higher tier serves is ABSENT on a lower one rather than false;
// a populated detail object carries its documented keys; an empty one means its flag is false.
public class LookupTests
{
    [Fact]
    public async Task AnUnauthenticatedLookupAnswersIpAndIsVpn()
    {
        var fixture = await Staging.AnswerFor(Rung.Unauth);

        Assert.Equal(Staging.Probe, fixture.Raw.GetProperty("ip").GetString());
        Assert.True(fixture.Raw.GetProperty("is_vpn").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Staging.AssertServedByTier(fixture);
    }

    [Theory]
    [InlineData("free")]
    [InlineData("starter")]
    [InlineData("scale")]
    [InlineData("max")]
    public async Task AKeyReachesTheWireAndItsAnswerKeepsItsShape(string tier)
    {
        var rung = Rung.All.Single(r => r.Tier == tier);
        rung.SkipUnlessKeyed();

        Staging.AssertServedByTier(await Staging.AnswerFor(rung));
    }

    [Fact]
    public async Task EachTierServesASupersetOfTheTierBelow()
    {
        Rung.SkipUnlessLadder();

        Fixture? below = null;
        foreach (var rung in Rung.Observable)
        {
            var fixture = await Staging.AnswerFor(rung);
            Console.WriteLine($"{rung.Tier}: {fixture.ServedFields.Count} fields");
            if (below is null)
            {
                below = fixture;
                continue;
            }
            foreach (var field in below.ServedFields)
            {
                Assert.True(
                    fixture.ServedFields.Contains(field),
                    $"{rung.Tier} drops {field}, which {below.Tier.Tier} serves");
            }
            // Without this a run in which every key resolved to the same plan would pass:
            // identical sets satisfy containment in both directions.
            if (rung.Widens)
            {
                Assert.True(
                    fixture.ServedFields.Count > below.ServedFields.Count,
                    $"{rung.Tier} answers {fixture.ServedFields.Count} field(s) and {below.Tier.Tier} "
                    + $"answers {below.ServedFields.Count}, so it is no wider");
            }
            below = fixture;
        }
    }

    [Fact]
    public async Task AFieldAHigherTierServesIsAbsentOnALowerOneNeverFalse()
    {
        Rung.SkipUnlessLadder();

        var open = Rung.Observable;
        var fixtures = new List<Fixture>();
        foreach (var rung in open)
        {
            fixtures.Add(await Staging.AnswerFor(rung));
        }

        // The positive half: a field the wire carried must have reached the result, which is what
        // makes a served `false` survive a mapper that copied on truthiness instead of presence.
        foreach (var fixture in fixtures)
        {
            foreach (var field in fixture.ServedFields.Where(Staging.IsModelled))
            {
                Assert.True(
                    Staging.ServedMember(fixture.Result, field) is not null,
                    $"{fixture.Tier.Tier} serves {field} and the client dropped it");
            }
        }

        for (var i = 0; i < fixtures.Count; i++)
        {
            var lower = fixtures[i];
            var higher = fixtures.Skip(i + 1).SelectMany(f => f.ServedFields).Distinct().Order();
            foreach (var field in higher)
            {
                if (lower.ServedFields.Contains(field) || !Staging.IsModelled(field))
                {
                    continue;
                }
                var value = Staging.ServedMember(lower.Result, field);
                Assert.True(
                    value is null,
                    $"{field} is not in the {lower.Tier.Tier} plan, so the result must not read as {value}");
            }
        }
    }

    [Fact]
    public async Task ABogonIsAnsweredWithoutTouchingTheNetwork()
    {
        using var client = new VpnDetectionClient(new VpnDetectionClientOptions
        {
            BaseUrl = Staging.BaseUrl,
            HttpClient = new HttpClient(new RefusingHandler()),
        });

        var result = await client.LookupAsync("10.0.0.1");

        Assert.True(result.IsBogon, "a private address must be answered locally");
        Assert.False(result.IsVpn, "a private address cannot be VPN infrastructure");
        Assert.True(Bogon.IsBogon("10.0.0.1"), "the standalone function must agree with the client");
        Assert.True(client.IsBogon("10.0.0.1"));
        // Computed rather than served, so it carries every field whatever the plan.
        foreach (var name in Staging.Members.Keys)
        {
            Assert.Equal(false, Staging.ServedMember(result, "is_" + name));
            Assert.NotNull(Staging.ServedMember(result, name));
        }
    }

    [Fact]
    public async Task ABatchCollapsesDuplicatesAndKeepsBogonsOffTheWire()
    {
        var (client, recorder) = Staging.ClientFor(Rung.Unauth);
        using (client)
        {
            var answers = await client.LookupBatchAsync(
                new[] { Staging.Probe, "8.8.8.8", Staging.Probe, "10.0.0.1", "8.8.8.8" });

            Assert.Equal(3, answers.Count);
            // Distinct paths rather than a call count, so a retry against a wobbling staging cannot
            // read as a failure to deduplicate.
            var asked = recorder.Seen.Select(fact => fact.Path).Distinct().Order().ToArray();
            Assert.Equal(new[] { "/" + Staging.Probe, "/8.8.8.8" }, asked);
            Assert.True(answers["10.0.0.1"].Result?.IsBogon, "10.0.0.1 was not answered locally");
            foreach (var ip in new[] { Staging.Probe, "8.8.8.8" })
            {
                Assert.True(answers[ip].IsSuccess, $"{ip} failed: {answers[ip].Error?.Message}");
            }
        }
    }

    private sealed class RefusingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("the bogon path reached the network");
    }
}
