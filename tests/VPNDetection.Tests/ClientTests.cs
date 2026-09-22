using System.Diagnostics;

using Xunit;

namespace VPNDetection.Tests;

// The .NET-specific API surface, as distinct from the shared conformance corpus in
// ConformanceTests.
public class ClientTests
{
    // Enough addresses for seven chunks of the batch endpoint's 1000, so a concurrency bound has
    // something to bound: one request per chunk, and only the chunks overlap.
    private static readonly string[] Addresses =
        Enumerable.Range(0, 6001).Select(i => $"9.{1 + i / 65536}.{i / 256 % 256}.{i % 256}").ToArray();

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

        Assert.Equal(7, handler.Calls.Count);
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

    // No cap on what one call accepts: chunking to the endpoint's 1000 is this library's job, so
    // 2,500 addresses is three requests rather than an error.
    [Fact]
    public async Task ABatchIsNeverCappedAndIsSentAsOnePostPerChunk()
    {
        var addresses = Enumerable.Range(0, 2500).Select(i => $"9.9.{i / 256}.{i % 256}").ToArray();
        var requests = new List<string>();
        var handler = new StubHandler(request =>
        {
            var ips = StubHandler.Ips(request);
            lock (requests)
            {
                requests.Add($"{request.Method} {request.RequestUri!.AbsolutePath} {ips.Count}");
            }
            return StubHandler.Json(new Route(BatchAnswers.Of(ips)));
        });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });

        var got = await client.LookupBatchAsync(addresses);

        Assert.Equal(
            new[] { "POST /batch 1000", "POST /batch 1000", "POST /batch 500" },
            requests.Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(addresses, got.Keys.ToArray());
        foreach (var ip in addresses)
        {
            Assert.True(got[ip].IsSuccess, $"{ip} was not answered");
            Assert.Equal(ip, got[ip].Result!.Ip);
        }
    }

    // A limit of 0 admits nothing, and a batch waiting on it would never end.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task ABatchConcurrencyBelowOneIsRefusedBeforeAnyRequest(int concurrency)
    {
        var handler = StubHandler.Lookups(Stub.Route("9.9.9.9", Stub.LookupBody("9.9.9.9")));
        using var client = Stub.Client(handler);

        var error = await Assert.ThrowsAsync<VpnDetectionException>(() => client
            .LookupBatchAsync(new[] { "9.9.9.9" }, new BatchOptions { Concurrency = concurrency })
            .WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(ErrorKind.BadRequest, error.Kind);
        Assert.Empty(handler.Calls);
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
        // The answers arrive in one chunk, keyed by a dictionary with no order of its own, so a
        // map that enumerated the dictionary would report an arbitrary order.
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

    private const string EntitlementBody = """
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
    public async Task MyEntitlementReportsThePlanAndTheUsage()
    {
        var handler = StubHandler.Lookups(Stub.Route("api/v1/entitlement", EntitlementBody));
        using var client = Stub.Client(handler);

        var ent = await client.MyEntitlementAsync();

        Assert.Equal("max", ent.Plan.Key);
        Assert.Equal(580, ent.Usage.Requests);
        Assert.Equal(5000000, ent.Usage.Quota);
        // Null means NEVER stop, which is not the same as a limit of zero.
        Assert.Null(ent.Usage.HardLimit);
        Assert.Empty(ent.Apikey.AllowedCidrs);
    }

    [Fact]
    public async Task MyEntitlementIsNotCached()
    {
        // The whole point is what has been spent.
        var handler = StubHandler.Lookups(Stub.Route("api/v1/entitlement", EntitlementBody));
        using var client = Stub.Client(handler);

        await client.MyEntitlementAsync();
        await client.MyEntitlementAsync();

        Assert.Equal(2, handler.Calls.Count);
    }

    [Fact]
    public async Task MyEntitlementSurfacesAnUnauthorizedKey()
    {
        var handler = StubHandler.Lookups(
            Stub.Route("api/v1/entitlement", """{"error":"invalid API key"}""", 401));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 0 });

        await Assert.ThrowsAsync<VpnDetectionException>(() => client.MyEntitlementAsync());
    }

    // `Retry-After` is the server's number, and Task.Delay throws past ~49.7 days: through 5.2.2
    // each of these failed the call with a raw ArgumentOutOfRangeException after one request. Too
    // long to count, it is waited out on the client's own backoff, and the 429 is still a throttle
    // carrying the server's value.
    [Theory]
    [InlineData("4294968")]
    [InlineData("2147483647")]
    [InlineData("Fri, 31 Dec 9999 23:59:59 GMT")]
    public async Task ARetryAfterTooLongToCountIsWaitedOutOnTheBackoff(string header)
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route(
            """{"rc":"RATE_LIMITED"}""", 429, new Dictionary<string, string> { ["Retry-After"] = header })));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 1 });

        var started = Stopwatch.StartNew();
        var failure = await Record.ExceptionAsync(
            () => client.Database.ListAsync().WaitAsync(TimeSpan.FromSeconds(20)));

        Assert.Equal(2, handler.Calls.Count);
        var error = Assert.IsType<VpnDetectionException>(failure);
        Assert.Equal(ErrorKind.RateLimited, error.Kind);
        Assert.True(error.RetryAfter > Wire.LongestWait, $"kept {error.RetryAfter}");
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(5), $"took {started.ElapsedMilliseconds}ms");
    }

    // Every path is appended after a `/`, so a doubled one is another path: prod answers
    // `https://api.vpndetection.io//api/v1/database/list` with a 301, which failed every call. Through
    // 5.2.2 one trailing slash was dropped and a second doubled, for OAuth as for the database.
    [Theory]
    [InlineData("https://api.test/")]
    [InlineData("https://api.test//")]
    [InlineData("https://api.test///")]
    public async Task EveryTrailingSlashOnTheBaseUrlIsDropped(string baseUrl)
    {
        // Routed on a substring, so a doubled path still gets the body it asked for and the
        // assertion on the paths is what fails.
        var handler = new StubHandler(request => request.RequestUri!.AbsolutePath.Contains(".well-known")
            ? StubHandler.Json(new Route("""{"issuer":"i","authorization_endpoint":"a","token_endpoint":"t"}"""))
            : StubHandler.Json(new Route("""{"databases":[]}""")));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { BaseUrl = baseUrl });

        await client.Database.ListAsync();
        await client.Oauth.MetadataAsync();

        Assert.Equal(new[] { "/api/v1/database/list", "/.well-known/oauth-authorization-server" }, handler.Calls);
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
        // A batch arrives as one POST per chunk, so it is answered from the addresses in the body.
        return StubHandler.Json(new Route(BatchAnswers.Of(StubHandler.Ips(request))));
    }
}

internal sealed class SlowestFirstHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // A batch arrives as one POST per chunk and is answered from the addresses in the body; a
        // single lookup is still answered from its path, slowest first.
        var ips = StubHandler.Ips(request);
        if (ips.Count > 0)
        {
            return StubHandler.Json(new Route(BatchAnswers.Of(ips)));
        }
        var ip = request.RequestUri!.AbsolutePath.TrimStart('/');
        await Task.Delay(60 - (10 * int.Parse(ip[^1..])), cancellationToken);
        return StubHandler.Json(new Route(Stub.LookupBody(ip)));
    }
}

// The answer a batch gets from a handler that has nothing to say about any address: every address
// in the body, not a VPN.
internal static class BatchAnswers
{
    internal static string Of(IReadOnlyList<string> ips)
    {
        var results = string.Join(",", ips.Select(ip => $"\"{ip}\":{Stub.LookupBody(ip)}"));
        return "{\"results\":{" + results + "},\"errors\":{}}";
    }
}
