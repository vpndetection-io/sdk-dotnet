using System.Text.Json;

using Xunit;

namespace VPNDetection.Tests;

// Asserts the shared conformance corpus that every VPNDetection SDK asserts.
//
// The corpus is generated into testdata/ and is identical across languages, so a behavior that
// drifts here fails here rather than surfacing as two client libraries quietly disagreeing about
// the same address.
public class ConformanceTests
{
    [Fact]
    public void IsBogonMatchesTheCanonicalRanges()
    {
        foreach (var c in Corpus.Data.GetProperty("isBogon").EnumerateArray())
        {
            var ip = c.GetProperty("ip").GetString()!;
            Assert.True(
                Bogon.IsBogon(ip) == c.GetProperty("expect").GetBoolean(),
                $"{ip} ({c.GetProperty("why").GetString()})");
        }
    }

    // A server listening on :: sees every IPv4 visitor as ::ffff:a.b.c.d. Read whole that is inside
    // ::ffff:0:0/96, so an SDK that did not unmap answered each one locally as a bogon.
    [Fact]
    public async Task AnIpv4MappedAddressIsTheIpv4AddressItCarries()
    {
        foreach (var c in Corpus.Data.GetProperty("ipv4Mapped").EnumerateArray())
        {
            var ip = c.GetProperty("ip").GetString()!;
            var carries = c.GetProperty("carries").GetString()!;
            var expect = c.GetProperty("expect").GetBoolean();
            Assert.True(Bogon.IsBogon(ip) == expect, $"{ip}: IsBogon ({c.GetProperty("why").GetString()})");

            var handler = StubHandler.Lookups(Stub.Route(carries, Stub.LookupBody(carries)));
            using var client = Stub.Client(handler);
            var result = await client.LookupAsync(ip);
            Assert.Equal(carries, result.Ip);
            if (expect)
            {
                Assert.True(result.IsBogon, $"{ip}: answered locally");
                Assert.Empty(handler.Calls);
                continue;
            }
            Assert.Equal(new[] { "/" + carries }, handler.Calls);
            await client.LookupAsync(carries);
            Assert.Single(handler.Calls);

            // The mapped form alone: asked beside its plain form, a batch that sent the address as
            // given would still have been answered for the plain one.
            var sent = new List<string>();
            var batch = new StubHandler(request =>
            {
                var ips = StubHandler.Ips(request);
                lock (sent)
                {
                    sent.AddRange(ips);
                }
                var results = ips.Where(x => x == carries)
                    .ToDictionary(x => x, x => JsonDocument.Parse(Stub.LookupBody(x)).RootElement.Clone());
                var errors = ips.Where(x => x != carries)
                    .ToDictionary(x => x, _ => (object)new { status = 400, error = "not a valid IP address" });
                return StubHandler.Json(new Route(JsonSerializer.Serialize(new { results, errors })));
            });
            using var batchClient = Stub.Client(batch, new VpnDetectionClientOptions { Retries = 0 });
            var got = await batchClient.LookupBatchAsync(new[] { ip });
            Assert.Equal(new[] { ip }, got.Keys.ToArray());
            Assert.Equal(carries, got[ip].Result?.Ip);
            Assert.Equal(new[] { carries }, sent);
        }
    }

    [Fact]
    public async Task ABogonIsAnsweredLocallyInTheFullMaxShape()
    {
        var handler = StubHandler.Lookups(new Dictionary<string, Route>());
        using var client = Stub.Client(handler);

        var result = await client.LookupAsync("10.0.0.1");

        Assert.True(result.IsBogon);
        Assert.Equal("10.0.0.1", result.Ip);
        var shape = Corpus.Data.GetProperty("bogonResponse");
        foreach (var flag in shape.GetProperty("flagsFalse").EnumerateArray())
        {
            var name = flag.GetString()!;
            Assert.True(
                Equals(Corpus.Member(result, name), false), $"{name} must be present and false");
        }
        foreach (var detail in shape.GetProperty("emptyObjects").EnumerateArray())
        {
            var name = detail.GetString()!;
            Assert.Equal("{}", Corpus.AsWire(Corpus.Member(result, name)));
        }
        // Every member the shape names beside its two lists: the location, AS, company and abuse
        // contact with every field empty, the web list empty and the hostname an empty string.
        foreach (var member in shape.EnumerateObject())
        {
            if (member.Name is "why" or "flagsFalse" or "emptyObjects")
            {
                continue;
            }
            Corpus.AssertWire(member.Value, Corpus.Member(result, member.Name), $"{member.Name} must carry every field, empty");
        }
        Assert.Empty(handler.Calls);
    }

    [Fact]
    public async Task LookupPreservesAbsentVersusFalseAcrossEveryPlanShape()
    {
        foreach (var c in Corpus.Data.GetProperty("lookup").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var body = c.GetProperty("body");
            var ip = body.GetProperty("ip").GetString()!;
            var expect = c.GetProperty("expect");

            using var client = Stub.Client(StubHandler.Lookups(
                Stub.Route(ip, body.GetRawText(), c.GetProperty("status").GetInt32())));
            var result = await client.LookupAsync(ip);

            Assert.Equal(expect.GetProperty("ip").GetString(), result.Ip);
            Assert.Equal(expect.GetProperty("isBogon").GetBoolean(), result.IsBogon);

            if (expect.TryGetProperty("present", out var present))
            {
                foreach (var field in present.EnumerateObject())
                {
                    Assert.True(
                        Equals(Corpus.Member(result, field.Name), field.Value.GetBoolean()),
                        $"{name}: {field.Name} should be {field.Value}");
                }
            }
            foreach (var field in Each(expect, "absent"))
            {
                Assert.True(
                    Corpus.Member(result, field) is null,
                    $"{name}: {field} must be ABSENT, not false");
            }
            foreach (var field in Each(expect, "emptyPresent"))
            {
                Assert.Equal("{}", Corpus.AsWire(Corpus.Member(result, field)));
            }
            // Every other key is a member compared as JSON: a detail, the web list, the location,
            // AS, company and abuse contact, the hostname. None is skipped, so a key the corpus adds
            // fails here until the result carries it.
            foreach (var member in expect.EnumerateObject())
            {
                if (member.Name is "ip" or "isBogon" or "present" or "absent" or "emptyPresent")
                {
                    continue;
                }
                var value = Corpus.Member(result, member.Name);
                Corpus.AssertWire(member.Value, value, $"{name}: {member.Name}");
                AssertEveryKeyTyped(value, $"{name}: {member.Name}");
            }
        }
    }

    // Each vocabulary case serves a well-formed answer, and each `expect` path, wire names with a
    // number indexing a list, reads the same value off the typed result: the plan's name beside its
    // key, and a tier, standing, license type, format and outcome no published list holds (5.15.0
    // failed the call on each of the five, measured 2026-11-17).
    [Fact]
    public async Task EveryVocabularyCaseReadsAsServed()
    {
        var cases = Corpus.Data.GetProperty("vocabulary").GetProperty("cases").EnumerateArray().ToList();
        Assert.Equal(6, cases.Count);
        foreach (var c in cases)
        {
            var name = c.GetProperty("name").GetString()!;
            var call = c.GetProperty("call").GetString()!;
            var answer = c.GetProperty("answer").GetRawText();
            using var client = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(answer))));

            object typed = call switch
            {
                "myEntitlement" => await client.MyEntitlementAsync(),
                "listDatabases" => new Dictionary<string, object> { ["databases"] = await client.Database.ListAsync() },
                "listDownloads" => new Dictionary<string, object> { ["downloads"] = await client.Database.DownloadsAsync() },
                _ => throw new InvalidOperationException($"{name}: no call {call}"),
            };

            var read = JsonDocument.Parse(Corpus.AsWire(typed)).RootElement;
            foreach (var expect in c.GetProperty("expect").EnumerateObject())
            {
                var at = expect.Name.Split('.').Aggregate(read, (node, step)
                    => int.TryParse(step, out var index) ? node[index] : node.GetProperty(step));
                Assert.True(expect.Value.GetRawText() == at.GetRawText(),
                    $"{name}: {expect.Name} read {at.GetRawText()}, want {expect.Value.GetRawText()}");
            }
        }
    }

    [Fact]
    public async Task AnUnknownVocabularyValueIsNotAKnownOne()
    {
        var entitlement = Corpus.Data.GetProperty("vocabulary").GetProperty("cases").EnumerateArray()
            .Single(entry => entry.GetProperty("name").GetString() == "entitlement-tier-unknown");
        using var client = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(entitlement.GetProperty("answer").GetRawText()))));

        var plan = (await client.MyEntitlementAsync()).Plan;

        Assert.Equal("data", plan.Tier.Value);
        Assert.False(plan.Tier.IsKnown);
        Assert.Equal("Data", plan.Name);
    }

    // An AS number is 32 bits unsigned, so the private-use range from 4200000000 is past an int.
    [Fact]
    public async Task AnAsNumberPastAnIntReads()
    {
        const string body = """{"ip":"45.83.91.1","is_vpn":false,"asn":{"asn":4200000001,"name":"n","domain":"d","type":"isp","prefix":"45.83.91.0/24","country":"US","rpki_status":"unknown"}}""";
        using var client = Stub.Client(StubHandler.Lookups(Stub.Route("45.83.91.1", body)));

        var result = await client.LookupAsync("45.83.91.1");

        Assert.Equal(4200000001L, result.Asn!.Number);
    }

    [Fact]
    public async Task A429IsClassifiedByRetryAfterNotByItsStatus()
    {
        foreach (var c in Corpus.Data.GetProperty("errors").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var headers = c.GetProperty("headers").EnumerateObject()
                .ToDictionary(h => h.Name, h => h.Value.GetString()!);
            // No retries, so a retryable error still surfaces rather than looping.
            using var client = Stub.Client(
                StubHandler.Lookups(Stub.Route(
                    "1.1.1.1", c.GetProperty("body").GetRawText(), c.GetProperty("status").GetInt32(), headers)),
                new VpnDetectionClientOptions { Retries = 0 });

            var error = await Assert.ThrowsAsync<VpnDetectionException>(() => client.LookupAsync("1.1.1.1"));

            var expect = c.GetProperty("expect");
            Assert.Equal(expect.GetProperty("kind").GetString(), Wire(error.Kind));
            Assert.Equal(expect.GetProperty("retryable").GetBoolean(), error.Retryable);
            if (expect.TryGetProperty("message", out var message))
            {
                Assert.Equal(message.GetString(), error.Message);
            }
            if (expect.TryGetProperty("retryAfterSeconds", out var seconds))
            {
                Assert.Equal(TimeSpan.FromSeconds(seconds.GetInt32()), error.RetryAfter);
            }
            else
            {
                Assert.Null(error.RetryAfter);
            }
        }
    }

    [Fact]
    public async Task BatchDedupesShortCircuitsBogonsAndKeysByAddress()
    {
        var c = Corpus.Case("batch", "dedup-bogon-and-order-free-keying");
        var handler = StubHandler.Lookups(new Dictionary<string, Route>
        {
            ["1.1.1.1"] = new Route(Stub.LookupBody("1.1.1.1")),
            ["8.8.8.8"] = new Route(Stub.LookupBody("8.8.8.8")),
        });
        using var client = Stub.Client(handler);

        var got = await client.LookupBatchAsync(Inputs(c));

        var expect = c.GetProperty("expect");
        Assert.Equal(Strings(expect, "keys"), got.Keys.ToArray());
        Assert.Equal(expect.GetProperty("httpRequests").GetInt32(), handler.Calls.Count);
        foreach (var ip in Strings(expect, "bogonKeys"))
        {
            Assert.True(got[ip].Result!.IsBogon, $"{ip} should be a local answer");
        }
    }

    [Fact]
    public async Task OneBadAddressDoesNotLoseTheRestOfTheBatch()
    {
        var c = Corpus.Case("batch", "partial-failure-does-not-fail-the-batch");
        using var client = Stub.Client(
            StubHandler.Lookups(Stub.Route("1.1.1.1", Stub.LookupBody("1.1.1.1"))),
            new VpnDetectionClientOptions { Retries = 0 });

        var got = await client.LookupBatchAsync(Inputs(c));

        var expect = c.GetProperty("expect");
        Assert.Equal(Strings(expect, "keys"), got.Keys.ToArray());
        foreach (var ip in Strings(expect, "errorKeys"))
        {
            Assert.False(got[ip].IsSuccess, $"{ip} should carry its error");
            Assert.Equal(expect.GetProperty("errorKinds").GetProperty(ip).GetString(), Wire(got[ip].Error!.Kind));
        }
        Assert.False(got["1.1.1.1"].Result!.IsVpn);
    }

    [Fact]
    public async Task AServedIsBogonReachesTheResult()
    {
        var handler = StubHandler.Lookups(new Dictionary<string, Route>
        {
            ["8.8.8.8"] = new Route("""{"ip":"8.8.8.8","is_bogon":true,"is_vpn":false}"""),
            ["8.8.4.4"] = new Route("""{"ip":"8.8.4.4","is_bogon":false,"is_vpn":false}"""),
            ["1.1.1.1"] = new Route(Stub.LookupBody("1.1.1.1")),
        });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });

        Assert.True((await client.LookupAsync("8.8.8.8")).IsBogon, "lookup: the served true");
        Assert.False((await client.LookupAsync("1.1.1.1")).IsBogon, "lookup: an absent is_bogon is false");
        var got = await client.LookupBatchAsync(["8.8.8.8", "8.8.4.4"]);
        Assert.True(got["8.8.8.8"].Result!.IsBogon, "batch: the served true");
        Assert.False(got["8.8.4.4"].Result!.IsBogon, "batch: the served false");
    }

    // The JSON comparison passes through NSwag's AdditionalProperties for a key the generated type
    // lacks, so each served key must also have landed in a typed property, at any depth.
    private static void AssertEveryKeyTyped(object? value, string because)
    {
        switch (value)
        {
            case null or string or ValueType:
                return;
            case System.Collections.IEnumerable list:
                foreach (var item in list)
                {
                    AssertEveryKeyTyped(item, because);
                }
                return;
        }
        var type = value.GetType();
        foreach (var property in type.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
        {
            if (property.Name == "AdditionalProperties")
            {
                var extra = (IDictionary<string, object>?)property.GetValue(value);
                Assert.True(extra is null || extra.Count == 0,
                    $"{because}: {type.Name} read no typed member for {string.Join(", ", extra?.Keys ?? [])}");
            }
            else if (property.GetIndexParameters().Length == 0)
            {
                AssertEveryKeyTyped(property.GetValue(value), because);
            }
        }
    }

    // The corpus compares each detail as JSON, which NSwag's AdditionalProperties round-trips
    // whether or not the type has the member, so the typed property is asserted here.
    [Fact]
    public async Task AServedProviderNameIsATypedMemberOfEachDetail()
    {
        const string body = """
            {"ip":"9.9.9.9","is_vpn":true,"vpn":{"provider":"mullvad","provider_name":"Mullvad"},
             "hosting":{"provider":"m247","provider_name":"M247"},
             "dcproxy":{"provider":"brightdata","provider_name":"Bright Data"}}
            """;
        using var client = Stub.Client(StubHandler.Lookups(Stub.Route("9.9.9.9", body)));

        var result = await client.LookupAsync("9.9.9.9");

        Assert.Equal("Mullvad", result.Vpn!.ProviderName);
        Assert.Equal("M247", result.Hosting!.ProviderName);
        Assert.Equal("Bright Data", result.Dcproxy!.ProviderName);
        Assert.False(result.Vpn.AdditionalProperties?.ContainsKey("provider_name") ?? false);
    }

    [Fact]
    public async Task ACacheHitIssuesNoSecondRequest()
    {
        var c = Corpus.Case("batch", "cache-hit-issues-no-second-request");
        var handler = StubHandler.Lookups(Stub.Route("1.1.1.1", Stub.LookupBody("1.1.1.1")));
        using var client = Stub.Client(handler);

        for (var i = 0; i < c.GetProperty("repeat").GetInt32(); i++)
        {
            var got = await client.LookupBatchAsync(Inputs(c));
            Assert.Equal(Strings(c.GetProperty("expect"), "keys"), got.Keys.ToArray());
        }

        Assert.Equal(c.GetProperty("expect").GetProperty("httpRequests").GetInt32(), handler.Calls.Count);
    }

    // The second case pins that no cap refuses a batch past the endpoint's thousand.
    [Theory]
    [InlineData("chunks-of-one-thousand")]
    [InlineData("uncapped-input-is-chunked")]
    public async Task ALargeBatchIsSentInChunksOfAThousand(string name)
    {
        var c = Corpus.Case("batch", name);
        var routes = new Dictionary<string, Route>();
        foreach (var ip in Inputs(c))
        {
            routes[ip] = new Route(Stub.LookupBody(ip));
        }
        var handler = StubHandler.Lookups(routes);
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });

        var got = await client.LookupBatchAsync(Inputs(c));

        var expect = c.GetProperty("expect");
        Assert.Equal(expect.GetProperty("keyCount").GetInt32(), got.Count);
        Assert.Equal(expect.GetProperty("httpRequests").GetInt32(), handler.Calls.Count);
        foreach (var ip in Inputs(c))
        {
            Assert.True(got[ip].IsSuccess, $"{ip} should be answered for itself");
            Assert.Equal(ip, got[ip].Result!.Ip);
        }
    }

    // A per-entry failure carries no headers, so its 429 can only be a spent allowance, and a 500
    // is the server's; neither is retried per entry, because retries belong to the call and the
    // call succeeded.
    [Fact]
    public async Task AnEntryErrorIsClassifiedByItsStatus()
    {
        var c = Corpus.Case("batch", "an-entry-error-is-classified-by-its-status");
        var handler = StubHandler.Lookups(new Dictionary<string, Route>
        {
            ["1.1.1.1"] = new Route(Stub.LookupBody("1.1.1.1")),
            ["8.8.8.8"] = new Route("""{"error":"overage cap reached; raise or remove it in Billing"}""", 429),
            ["9.9.9.9"] = new Route("""{"error":"lookup failed"}""", 500),
        });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 3 });

        var got = await client.LookupBatchAsync(Inputs(c));

        var expect = c.GetProperty("expect");
        Assert.Equal(Strings(expect, "keys"), got.Keys.ToArray());
        foreach (var entry in expect.GetProperty("errorKinds").EnumerateObject())
        {
            Assert.False(got[entry.Name].IsSuccess, $"{entry.Name} should carry its error");
            Assert.Equal(entry.Value.GetString(), Wire(got[entry.Name].Error!.Kind));
        }
        Assert.Equal(expect.GetProperty("httpRequests").GetInt32(), handler.Calls.Count);
    }

    // ErrorKind.BadRequest is `bad_request` in the corpus. Spelling the mapping out beats making
    // the enum's own name a wire contract nobody can see.
    internal static string Wire(ErrorKind kind) => kind switch
    {
        ErrorKind.BadRequest => "bad_request",
        ErrorKind.Unauthorized => "unauthorized",
        ErrorKind.Forbidden => "forbidden",
        ErrorKind.RateLimited => "rate_limited",
        ErrorKind.QuotaExceeded => "quota_exceeded",
        ErrorKind.ServerError => "server_error",
        ErrorKind.Network => "network",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string[] Inputs(JsonElement batchCase) => Strings(batchCase, "input");

    private static string[] Strings(JsonElement parent, string name)
        => parent.TryGetProperty(name, out var array)
            ? array.EnumerateArray().Select(v => v.GetString()!).ToArray()
            : Array.Empty<string>();

    private static IEnumerable<string> Each(JsonElement parent, string name) => Strings(parent, name);
}
