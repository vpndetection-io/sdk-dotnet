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
            foreach (var detail in new[] { "vpn", "hosting", "dcproxy" })
            {
                if (expect.TryGetProperty(detail, out var want))
                {
                    Corpus.AssertWire(want, Corpus.Member(result, detail), $"{name}: {detail}");
                }
            }
        }
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
            Assert.NotNull(got[ip].Error);
        }
        Assert.False(got["1.1.1.1"].Result!.IsVpn);
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

    // ErrorKind.BadRequest is `bad_request` in the corpus. Spelling the mapping out beats making
    // the enum's own name a wire contract nobody can see.
    private static string Wire(ErrorKind kind) => kind switch
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
