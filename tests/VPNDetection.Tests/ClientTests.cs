using Xunit;

namespace VPNDetection.Tests;

// The .NET-specific API surface, as distinct from the shared conformance corpus in
// ConformanceTests.
public class ClientTests
{
    private static readonly string[] Addresses =
        Enumerable.Range(1, 12).Select(i => $"9.9.9.{i}").ToArray();

    [Fact]
    public void IsBogonIsOnTheClientAndAgreesWithTheStandaloneForm()
    {
        using var client = new VpnDetectionClient();
        foreach (var c in Corpus.Data.GetProperty("isBogon").EnumerateArray())
        {
            var ip = c.GetProperty("ip").GetString()!;
            Assert.True(
                client.IsBogon(ip) == c.GetProperty("expect").GetBoolean(),
                $"{ip} ({c.GetProperty("why").GetString()})");
            Assert.Equal(Bogon.IsBogon(ip), client.IsBogon(ip));
        }
    }

    [Fact]
    public async Task BatchConcurrencyIsConfigurablePerCall()
    {
        var handler = new ConcurrencyTrackingHandler();
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });

        await client.LookupBatchAsync(Addresses, new BatchOptions { Concurrency = 3 });

        Assert.Equal(Addresses.Length, handler.Calls.Count);
        Assert.True(handler.Peak <= 3, $"peak in flight was {handler.Peak}, expected at most 3");
        Assert.True(handler.Peak > 1, "requests should still overlap");
    }

    [Fact]
    public async Task APerCallConcurrencyOverridesTheClientDefault()
    {
        var handler = new ConcurrencyTrackingHandler();
        // Instance default of 2, raised to 6 for this one batch.
        using var client = Stub.Client(
            handler, new VpnDetectionClientOptions { CacheEnabled = false, Concurrency = 2 });

        await client.LookupBatchAsync(Addresses, new BatchOptions { Concurrency = 6 });

        Assert.True(handler.Peak > 2, $"override ignored: peak was {handler.Peak}, expected above 2");
        Assert.True(handler.Peak <= 6, $"peak in flight was {handler.Peak}, expected at most 6");
    }

    [Fact]
    public async Task WithoutAnOverrideTheClientConcurrencyStillApplies()
    {
        var handler = new ConcurrencyTrackingHandler();
        using var client = Stub.Client(
            handler, new VpnDetectionClientOptions { CacheEnabled = false, Concurrency = 2 });

        await client.LookupBatchAsync(Addresses);

        Assert.True(handler.Peak <= 2, $"peak in flight was {handler.Peak}, expected at most 2");
    }

    [Fact]
    public async Task RetriesAreConfigurablePerCall()
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route("""{"error":"lookup failed"}""", 500)));
        using var client = Stub.Client(
            handler, new VpnDetectionClientOptions { CacheEnabled = false, Retries = 0 });

        await Assert.ThrowsAsync<VpnDetectionException>(
            () => client.LookupAsync("9.9.9.9", new LookupOptions { Retries = 2 }));

        // 1 initial attempt plus 2 retries, rather than the instance's 0.
        Assert.Equal(3, handler.Calls.Count);
    }

    [Fact]
    public async Task RetriesAreConfigurablePerBatch()
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route("""{"error":"lookup failed"}""", 500)));
        using var client = Stub.Client(
            handler, new VpnDetectionClientOptions { CacheEnabled = false, Retries = 0 });

        var got = await client.LookupBatchAsync(new[] { "9.9.9.9" }, new BatchOptions { Retries = 1 });

        Assert.False(got["9.9.9.9"].IsSuccess);
        Assert.Equal(2, handler.Calls.Count);
    }

    [Fact]
    public async Task TwoClientsNeverShareACachedAnswer()
    {
        var handler = StubHandler.Lookups(Stub.Route("1.1.1.1", Stub.LookupBody("1.1.1.1")));
        using var a = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "key-a" });
        using var b = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "key-b" });

        await a.LookupAsync("1.1.1.1");
        await b.LookupAsync("1.1.1.1");

        // Two keys can be on different plans and so entitled to different fields; a shared cache
        // would serve one of them the other's shape.
        Assert.Equal(2, handler.Calls.Count);
    }

    [Fact]
    public async Task CachingCanBeTurnedOff()
    {
        var handler = StubHandler.Lookups(Stub.Route("1.1.1.1", Stub.LookupBody("1.1.1.1")));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });

        await client.LookupAsync("1.1.1.1");
        await client.LookupAsync("1.1.1.1");

        Assert.Equal(2, handler.Calls.Count);
    }

    [Fact]
    public async Task TheApiKeyIsSentAsABearerTokenAndOmittedWithoutOne()
    {
        var seen = new List<string?>();
        var handler = new StubHandler(request =>
        {
            seen.Add(request.Headers.Authorization?.ToString());
            return StubHandler.Json(new Route(Stub.LookupBody("1.1.1.1")));
        });
        using var keyed = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "abc123" });
        using var keyless = Stub.Client(handler);

        await keyed.LookupAsync("1.1.1.1");
        await keyless.LookupAsync("1.1.1.1");

        Assert.Equal(new string?[] { "Bearer abc123", null }, seen);
    }

    [Fact]
    public async Task ABatchIsKeyedInInputOrderRegardlessOfWhichAddressAnswersFirst()
    {
        // The last address answers first, so a map that enumerated in completion order would
        // report the reverse.
        var handler = new SlowestFirstHandler();
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });

        var got = await client.LookupBatchAsync(new[] { "9.9.9.1", "9.9.9.2", "9.9.9.3" });

        Assert.Equal(new[] { "9.9.9.1", "9.9.9.2", "9.9.9.3" }, got.Keys.ToArray());
        Assert.Equal(3, got.Count);
        Assert.True(got.ContainsKey("9.9.9.2"));
        Assert.True(got.TryGetValue("9.9.9.3", out var third) && third.IsSuccess);
    }

    [Fact]
    public async Task ACancelledLookupSurfacesAsCancellationNotAsANetworkError()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        using var client = Stub.Client(
            StubHandler.Lookups(Stub.Route("1.1.1.1", Stub.LookupBody("1.1.1.1"))));

        // Wire only reclassifies a cancellation the CALLER did not ask for, which is how an
        // HttpClient timeout is told apart from a token the caller cancelled.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.LookupAsync("1.1.1.1", cts.Token));
    }

    private const string AccountBody = """
        {
          "org_id": "85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61",
          "apikey": {
            "id": "0ab424cc-7619-4dad-b027-afacdc2cedb0",
            "expires": null,
            "allowed_cidrs": []
          },
          "plan": {"key": "max", "tier": "max"},
          "usage": {
            "requests": 580,
            "quota": 5000000,
            "hard_limit": null,
            "window_start": "2026-09-04T07:00:00Z",
            "window_end": "2026-10-04T07:00:00Z"
          }
        }
        """;

    [Fact]
    public async Task MyIpClassifiesTheCallingAddress()
    {
        var handler = StubHandler.Lookups(Stub.Route("myip", Stub.LookupBody("45.83.91.1", isVpn: true)));
        using var client = Stub.Client(handler);

        var result = await client.MyIpAsync();

        Assert.Equal("45.83.91.1", result.Ip);
        Assert.True(result.IsVpn);
    }

    [Fact]
    public async Task MyIpIsNotCached()
    {
        // The cache is keyed by address, and which address this is IS the question.
        var handler = StubHandler.Lookups(Stub.Route("myip", Stub.LookupBody("45.83.91.1", isVpn: true)));
        using var client = Stub.Client(handler);

        await client.MyIpAsync();
        await client.MyIpAsync();

        Assert.Equal(2, handler.Calls.Count);
    }

    [Fact]
    public async Task MyAccountReportsThePlanAndTheUsage()
    {
        var handler = StubHandler.Lookups(Stub.Route("api/v1/account/me", AccountBody));
        using var client = Stub.Client(handler);

        var account = await client.MyAccountAsync();

        Assert.Equal("max", account.Plan.Key);
        Assert.Equal(580, account.Usage.Requests);
        Assert.Equal(5000000, account.Usage.Quota);
        // Null means NEVER stop, which is not the same as a limit of zero.
        Assert.Null(account.Usage.HardLimit);
        Assert.Empty(account.Apikey.AllowedCidrs);
    }

    [Fact]
    public async Task MyAccountIsNotCached()
    {
        // The whole point is what has been spent.
        var handler = StubHandler.Lookups(Stub.Route("api/v1/account/me", AccountBody));
        using var client = Stub.Client(handler);

        await client.MyAccountAsync();
        await client.MyAccountAsync();

        Assert.Equal(2, handler.Calls.Count);
    }

    [Fact]
    public async Task MyAccountSurfacesAnUnauthorizedKey()
    {
        var handler = StubHandler.Lookups(
            Stub.Route("api/v1/account/me", """{"error":"invalid API key"}""", 401));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 0 });

        await Assert.ThrowsAsync<VpnDetectionException>(() => client.MyAccountAsync());
    }
}

// Answers slowly enough that concurrent calls overlap, and records the peak number in flight.
// Asserting the PEAK is the only way to tell a real limit from an option that was accepted and
// ignored.
internal sealed class ConcurrencyTrackingHandler : HttpMessageHandler
{
    private readonly List<string> calls = new();
    private int inFlight;

    internal int Peak { get; private set; }

    internal IReadOnlyList<string> Calls
    {
        get
        {
            lock (calls)
            {
                return calls.ToArray();
            }
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (calls)
        {
            calls.Add(request.RequestUri!.PathAndQuery);
            inFlight++;
            Peak = Math.Max(Peak, inFlight);
        }
        await Task.Delay(20, cancellationToken);
        lock (calls)
        {
            inFlight--;
        }
        var ip = request.RequestUri!.AbsolutePath.TrimStart('/');
        return StubHandler.Json(new Route(Stub.LookupBody(ip)));
    }
}

internal sealed class SlowestFirstHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var ip = request.RequestUri!.AbsolutePath.TrimStart('/');
        await Task.Delay(60 - (10 * int.Parse(ip[^1..])), cancellationToken);
        return StubHandler.Json(new Route(Stub.LookupBody(ip)));
    }
}
