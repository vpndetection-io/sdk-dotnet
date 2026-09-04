using System.Text.Json;

using Xunit;

namespace VPNDetection.Integration;

// The staging fixtures the test files share: one client per tier, one lookup per tier, and the
// shape rules that hold whatever the plan.
internal static class Staging
{
    internal const string BaseUrl = "https://api-staging.vpndetection.io";

    /// <summary>A stable VPN address, and the one the README teaches.</summary>
    internal const string Probe = "45.83.91.1";

    // One entry per dataset the API answers about. Required is what a POPULATED detail object
    // carries on every tier; Optional is the max-only remainder, which is absent rather than empty
    // on a lower plan.
    private static readonly string[] ClassKeys = { "provider", "confidence", "last_seen" };

    private static readonly string[] ProxyKeys =
        { "provider", "first_seen", "last_seen", "hits", "hits_days_pct", "providers_num" };

    internal static readonly IReadOnlyDictionary<string, Detail> Members = new Dictionary<string, Detail>
    {
        ["vpn"] = new(new[] { "provider", "last_seen" }, new[] { "confidence", "method" }),
        ["hosting"] = new(ClassKeys, Array.Empty<string>()),
        ["relay"] = new(ClassKeys, Array.Empty<string>()),
        ["tor"] = new(ClassKeys, Array.Empty<string>()),
        ["cdn"] = new(ClassKeys, Array.Empty<string>()),
        ["resproxy"] = new(ProxyKeys, Array.Empty<string>()),
        ["dcproxy"] = new(ProxyKeys, Array.Empty<string>()),
        ["mobproxy"] = new(ProxyKeys, Array.Empty<string>()),
    };

    private static readonly SemaphoreSlim AnswersLock = new(1, 1);
    private static readonly Dictionary<string, Fixture> Answers = new();

    internal record Detail(IReadOnlyList<string> Required, IReadOnlyList<string> Optional);

    /// <summary>A client on one rung, wired to staging through a handler that records what it saw.</summary>
    internal static (VpnDetectionClient Client, RecordingHandler Recorder) ClientFor(Rung rung)
    {
        // Redirects off, exactly as the library's own handler configures them: the download
        // endpoint's 302 must reach the library rather than the transport.
        var recorder = new RecordingHandler(rung.Key, new HttpClientHandler { AllowAutoRedirect = false });
        var options = new VpnDetectionClientOptions
        {
            BaseUrl = BaseUrl,
            HttpClient = new HttpClient(recorder),
        };
        if (rung.Key.Length > 0)
        {
            options.ApiKey = rung.Key;
        }
        return (new VpnDetectionClient(options), recorder);
    }

    /// <summary>
    /// One lookup per tier for the whole run. The client caches, so a second reader of the same
    /// tier would cost no request either, but the fixture also carries what the WIRE said, which
    /// the client does not keep.
    /// </summary>
    internal static async Task<Fixture> AnswerFor(Rung rung)
    {
        await AnswersLock.WaitAsync();
        try
        {
            if (Answers.TryGetValue(rung.Tier, out var known))
            {
                return known;
            }
            var (client, recorder) = ClientFor(rung);
            using (client)
            {
                var result = await client.LookupAsync(Probe);
                var fixture = new Fixture(rung, result, recorder.JsonBody("/" + Probe), recorder.CarriedKey);
                // Checked here rather than in one test, so no comparison anywhere can be made
                // against a tier that silently ran unauthenticated: an empty or unsent key answers
                // the free shape, which satisfies every containment check vacuously.
                Assert.True(rung.Secret is null || fixture.CarriedKey, $"the {rung.Tier} key never reached the wire");
                Answers[rung.Tier] = fixture;
                return fixture;
            }
        }
        finally
        {
            AnswersLock.Release();
        }
    }

    internal static void AssertServedByTier(Fixture fixture)
    {
        Assert.Equal(Probe, fixture.Result.Ip);
        Assert.False(fixture.Result.IsBogon, "a served answer is not a local one");
        AssertShape(fixture.Tier.Tier, fixture.Result, fixture.Raw);
    }

    // Holds on every plan: presence is the plan, the value is the answer.
    private static void AssertShape(string tier, Result result, JsonElement raw)
    {
        Assert.Equal(JsonValueKind.String, raw.GetProperty("ip").ValueKind);
        var served = raw.GetProperty("is_vpn");
        Assert.True(
            served.ValueKind is JsonValueKind.True or JsonValueKind.False,
            $"{tier}: is_vpn is {served}, and it is on every plan");
        Assert.Equal(served.GetBoolean(), result.IsVpn);

        foreach (var (name, spec) in Members)
        {
            var flag = "is_" + name;
            if (raw.TryGetProperty(flag, out var flagValue))
            {
                Assert.True(
                    flagValue.ValueKind is JsonValueKind.True or JsonValueKind.False,
                    $"{tier}: {flag} is present, so it must be a real boolean, not {flagValue}");
            }
            if (!raw.TryGetProperty(name, out var detail))
            {
                continue;
            }
            // A detail object without its flag would leave a caller reading the object to find out
            // whether the address is flagged at all.
            Assert.True(raw.TryGetProperty(flag, out _), $"{tier}: {name} is served without {flag}");
            AssertDetail(tier, name, spec, detail, raw.GetProperty(flag).GetBoolean());
        }
    }

    private static void AssertDetail(string tier, string name, Detail spec, JsonElement detail, bool flag)
    {
        Assert.Equal(JsonValueKind.Object, detail.ValueKind);
        var keys = detail.EnumerateObject().Select(field => field.Name).ToArray();
        if (keys.Length == 0)
        {
            Assert.False(flag, $"{tier}: {name} is empty, so is_{name} must be false");
            return;
        }
        foreach (var key in spec.Required)
        {
            Assert.True(keys.Contains(key), $"{tier}: {name} is populated but carries no {key}");
        }
        foreach (var key in keys)
        {
            Assert.True(
                spec.Required.Contains(key) || spec.Optional.Contains(key),
                $"{tier}: {name}.{key} is not a documented key of this detail object");
        }
    }

    /// <summary>
    /// Reads a member of the answer by its WIRE name, so a test says "this field is absent" about
    /// the name the API serves rather than whatever the generator called it.
    /// </summary>
    /// <remarks>
    /// Every tier-gated member is nullable and copied on PRESENCE, so null is a field the plan did
    /// not include and a served <c>false</c> is still a member that is there. <c>ip</c> and
    /// <c>is_vpn</c> are on every plan and so are never null.
    /// </remarks>
    internal static object? ServedMember(Result result, string wire)
    {
        var property = typeof(Result).GetProperty(Pascal(wire));
        return property?.GetValue(result);
    }

    /// <summary>Whether the client models this wire name at all.</summary>
    /// <remarks>
    /// A field the client does not model is the API moving ahead of the pinned spec, not a drop.
    /// </remarks>
    internal static bool IsModelled(string wire) => typeof(Result).GetProperty(Pascal(wire)) is not null;

    private static string Pascal(string wire)
        => string.Concat(wire.Split('_').Select(part => char.ToUpperInvariant(part[0]) + part[1..]));
}

/// <summary>One tier's answer, plus the two facts the client itself does not keep.</summary>
internal sealed record Fixture(Rung Tier, Result Result, JsonElement Raw, bool CarriedKey)
{
    /// <summary>The wire field names this answer carried.</summary>
    internal IReadOnlyCollection<string> ServedFields
        => Raw.EnumerateObject().Select(field => field.Name).ToArray();
}
