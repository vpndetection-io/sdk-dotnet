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
    public async Task ALookupWithoutAKeyAnswersIpAndIsVpnAtTheLeast()
    {
        var fixture = await Staging.AnswerFor(Rung.Unauth);

        Assert.Equal(Staging.Probe, fixture.Raw.GetProperty("ip").GetString());
        Assert.True(fixture.Raw.GetProperty("is_vpn").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Staging.AssertServedByTier(fixture);
    }

    [Theory]
    [InlineData("trial")]
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
            var fields = TierFields(fixture);
            Console.WriteLine($"{rung.Tier}: {fields.Count} fields");
            if (below is null)
            {
                below = fixture;
                continue;
            }
            var lower = TierFields(below);
            foreach (var field in lower)
            {
                Assert.True(fields.Contains(field), $"{rung.Tier} drops {field}, which {below.Tier.Tier} serves");
            }
            // Without this a run in which every key resolved to the same plan would pass:
            // identical sets satisfy containment in both directions.
            if (rung.Widens)
            {
                Assert.True(
                    fields.Count > lower.Count,
                    $"{rung.Tier} answers {fields.Count} field(s) and {below.Tier.Tier} "
                    + $"answers {lower.Count}, so it is no wider");
            }
            if (rung.Tier != "trial")
            {
                below = fixture;
            }
        }
    }

    // The fields a tier serves: trial_expired marks a trial key's answers, and no other, so it is
    // not one.
    private static HashSet<string> TierFields(Fixture fixture)
        => fixture.ServedFields.Where(field => field != "trial_expired").ToHashSet();

    [Fact]
    public async Task ATrialKeysAnswerIsAPaidOneOrUnlimitedsAndSaysWhich()
    {
        Rung.Trial.SkipUnlessKeyed();
        var raw = (await Staging.AnswerFor(Rung.Trial)).Raw;

        Assert.True(raw.TryGetProperty("trial_expired", out var expired), "a trial key answers trial_expired");
        Assert.True(expired.ValueKind is JsonValueKind.True or JsonValueKind.False);
        // The organization's first 100 lookups of the UTC day are answered in full, and the rest as
        // Unlimited's: which half a run sees depends on the day.
        Assert.Equal(expired.ValueKind == JsonValueKind.False, raw.TryGetProperty("is_hosting", out _));
    }

    [Fact]
    public async Task ATrialKeysBatchOfTwoIsRefusedAsABadRequestOnce()
    {
        Rung.Trial.SkipUnlessKeyed();
        var (client, recorder) = Staging.ClientFor(Rung.Trial);
        using (client)
        {
            var answers = await client.LookupBatchAsync(new[] { Staging.Probe, "8.8.8.8" });

            foreach (var ip in new[] { Staging.Probe, "8.8.8.8" })
            {
                var refused = answers[ip].Error;
                Assert.NotNull(refused);
                Assert.Equal(ErrorKind.BadRequest, refused.Kind);
                Assert.Equal(402, refused.StatusCode);
                Assert.False(refused.Retryable);
            }
            Assert.Equal(new[] { "/batch" }, recorder.Seen.Select(fact => fact.Path).ToArray());
        }
    }

    [Fact]
    public async Task ATrialKeysBatchOfOneIsAnswered()
    {
        Rung.Trial.SkipUnlessKeyed();
        var (client, recorder) = Staging.ClientFor(Rung.Trial);
        using (client)
        {
            var answers = await client.LookupBatchAsync(new[] { Staging.Probe });

            var answer = answers[Staging.Probe];
            Assert.True(answer.IsSuccess, $"a trial key's batch of one failed: {answer.Error?.Message}");
            // Read off the wire, since the client this suite resolves may predate the member.
            var served = recorder.JsonBody("/batch").GetProperty("results").GetProperty(Staging.Probe);
            Assert.True(
                served.TryGetProperty("trial_expired", out var expired)
                    && expired.ValueKind is JsonValueKind.True or JsonValueKind.False,
                "the answer carries trial_expired");
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
    public async Task ABatchWithoutAKeyIsRefusedOnceAndItsBogonStillAnswered()
    {
        var (client, recorder) = Staging.ClientFor(Rung.Unauth);
        using (client)
        {
            var answers = await client.LookupBatchAsync(new[] { Staging.Probe, "10.0.0.1" });

            Assert.True(answers["10.0.0.1"].Result?.IsBogon, "10.0.0.1 was not answered locally");
            var refused = answers[Staging.Probe].Error;
            Assert.NotNull(refused);
            Assert.Equal(ErrorKind.Unauthorized, refused.Kind);
            Assert.Equal(401, refused.StatusCode);
            Assert.False(refused.Retryable);
            Assert.Equal(new[] { "/batch" }, recorder.Seen.Select(fact => fact.Path).ToArray());
        }
    }

    [Fact]
    public async Task ABatchCollapsesDuplicatesAndKeepsBogonsOffTheWire()
    {
        // A batch needs a paid plan, and starter is the cheapest.
        Rung.Paid.SkipUnlessKeyed();
        var (client, recorder) = Staging.ClientFor(Rung.Paid);
        using (client)
        {
            var answers = await client.LookupBatchAsync(
                new[] { Staging.Probe, "8.8.8.8", Staging.Probe, "10.0.0.1", "8.8.8.8" });

            Assert.Equal(3, answers.Count);
            // The two routable addresses go out together as one POST /batch. Distinct paths rather
            // than a call count, so a retry against a wobbling staging cannot read as a failure to
            // deduplicate.
            var asked = recorder.Seen.Select(fact => fact.Path).Distinct().ToArray();
            Assert.Equal(new[] { "/batch" }, asked);
            Assert.True(recorder.CarriedKey, "the paid key never reached the wire");
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
