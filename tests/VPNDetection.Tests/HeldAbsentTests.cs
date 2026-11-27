using System.Text.Json.Nodes;

using VPNDetection.Middleware;

using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// The AS's <c>type</c>, which the API will not answer to Unlimited: a lookup may lack it, it keeps
/// its non-optional public type until the next major so an absent one reads empty, a type that is
/// there is read as served, and the middleware still sees the one the wire left out as a plan gap.
/// </summary>
public class HeldAbsentTests
{
    private const string Ip = "146.70.116.130";

    private static readonly Condition[] TypeIsHosting =
        [new Condition { ["asn"] = new Condition { ["type"] = "hosting" } }];

    private static JsonObject Paid() => JsonNode.Parse(
        $$$"""{"ip":"{{{Ip}}}","is_vpn":true,"asn":{"asn":9009,"name":"M247 Europe SRL","domain":"m247global.com","type":"hosting","prefix":"146.70.116.0/24","country":"RO","rpki_status":"valid"}}""")!.AsObject();

    private static JsonObject Unlimited()
    {
        var body = Paid();
        Assert.True(body["asn"]!.AsObject().Remove("type"));
        return body;
    }

    private static async Task<Result> Read(string call, JsonObject body)
    {
        var served = call == "batch"
            ? new JsonObject { ["results"] = new JsonObject { [Ip] = body }, ["errors"] = new JsonObject() }.ToJsonString()
            : body.ToJsonString();
        var handler = new StubHandler(_ => StubHandler.Json(new Route(served)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { CacheEnabled = false });
        switch (call)
        {
            case "lookup":
                return await client.LookupAsync(Ip);
            case "myIp":
                return await client.MyIpAsync();
            default:
                var answers = await client.LookupBatchAsync([Ip]);
                return answers[Ip].Result ?? throw new Xunit.Sdk.XunitException("the batch entry was not read");
        }
    }

    [Theory]
    [InlineData("lookup")]
    [InlineData("batch")]
    [InlineData("myIp")]
    public async Task AnAnswerWithoutTheAsTypeReadsItEmptyAndReportsItMissingByItsPath(string call)
    {
        var result = await Read(call, Unlimited());

        Assert.Equal(string.Empty, result.Asn!.Type);
        Assert.Equal("M247 Europe SRL", result.Asn.Name);
        Assert.Equal("RO", result.Asn.Country);
        Assert.Equal(["asn.type"], Condition.MissingMembers(TypeIsHosting, result));
        Assert.False(Condition.Matches(TypeIsHosting, result));
        Assert.Empty(Condition.MissingMembers([new Condition { ["asn"] = new Condition { ["name"] = "m247 europe srl" } }], result));
    }

    [Fact]
    public async Task AnEmptyTypeIsNeverReadAsAValueTheAnswerSent()
    {
        var result = await Read("lookup", Unlimited());

        Assert.False(Condition.Matches([new Condition { ["asn"] = new Condition { ["type"] = string.Empty } }], result));
        Assert.False(Condition.Matches([new Condition { ["asn"] = new Condition { ["type"] = new[] { "", "isp" } } }], result));
    }

    [Fact]
    public async Task TheAsTypeThatIsThereIsReadAsServedAndIsNotAPlanGap()
    {
        var result = await Read("lookup", Paid());

        Assert.Equal("hosting", result.Asn!.Type);
        Assert.Empty(Condition.MissingMembers(TypeIsHosting, result));
        Assert.True(Condition.Matches(TypeIsHosting, result));
    }

    [Fact]
    public async Task AnAsTypeServedEmptyIsAValueAndNotAPlanGap()
    {
        var body = Paid();
        body["asn"]!["type"] = string.Empty;

        var result = await Read("lookup", body);

        Assert.Equal(string.Empty, result.Asn!.Type);
        Assert.Empty(Condition.MissingMembers(TypeIsHosting, result));
        Assert.True(Condition.Matches([new Condition { ["asn"] = new Condition { ["type"] = new[] { "", "isp" } } }], result));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task AnAsTypeThatIsNullOrNotAStringIsARetriedServerError(string form)
    {
        var body = Paid();
        body["asn"]!["type"] = JsonNode.Parse(form);
        var handler = new StubHandler(_ => StubHandler.Json(new Route(body.ToJsonString())));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 1, CacheEnabled = false });

        var failure = await Assert.ThrowsAsync<VpnDetectionException>(() => client.LookupAsync(Ip));

        Assert.Equal(ErrorKind.ServerError, failure.Kind);
        Assert.Equal(200, failure.StatusCode);
        Assert.Equal(2, handler.Calls.Count);
    }

    // The answer is cached whole, so the cached copy must still know the wire left the type out.
    [Fact]
    public async Task ACachedAnswerStillKnowsTheWireLeftTheAsTypeOut()
    {
        var handler = StubHandler.Lookups(Stub.Route(Ip, Unlimited().ToJsonString()));
        using var client = Stub.Client(handler);

        var first = await client.LookupAsync(Ip);
        var cached = await client.LookupAsync(Ip);

        Assert.Single(handler.Calls);
        Assert.Same(first.Raw, cached.Raw);
        Assert.Equal(string.Empty, cached.Asn!.Type);
        Assert.Equal(["asn.type"], Condition.MissingMembers(TypeIsHosting, cached));
        Assert.False(Condition.Matches(TypeIsHosting, cached));
    }

    // A bogon is answered here, whole, with the type empty because it carries nothing: no gap.
    [Fact]
    public async Task ALocalBogonAnswerCarriesTheAsTypeAndItIsNoPlanGap()
    {
        using var client = Stub.Client(new StubHandler(_ => throw new InvalidOperationException("no request")));

        var bogon = await client.LookupAsync("10.0.0.7");

        Assert.Empty(Condition.MissingMembers(TypeIsHosting, bogon));
        Assert.False(Condition.Matches(TypeIsHosting, bogon));
    }

    // Through the middleware core, with the answer the API will give a keyless visitor: the term
    // never blocks, and the report names the member by its path, as OnMissingField says.
    [Fact]
    public async Task AConditionOnTheAsTypeNeverBlocksAKeylessVisitorAndIsReportedByItsPath()
    {
        var warnings = new List<string>();
        var core = new Core<string>(
            new MiddlewareOptions<string>
            {
                Client = Stub.Client(StubHandler.Lookups(Stub.Route(Ip, Unlimited().ToJsonString()))),
                BlockCondition = TypeIsHosting,
                OnWarn = warnings.Add,
            },
            request => request);

        var lookup = await core.EvaluateAsync(Ip);
        await core.EvaluateAsync(Ip);

        Assert.False(lookup!.Blocked);
        Assert.Equal(string.Empty, lookup.Result!.Asn!.Type);
        var warning = Assert.Single(warnings);
        Assert.Contains("asn.type", warning);
    }

    [Fact]
    public async Task AConditionOnTheAsTypeThrowsWhereOnMissingFieldSaysSo()
    {
        var core = new Core<string>(
            new MiddlewareOptions<string>
            {
                Client = Stub.Client(StubHandler.Lookups(Stub.Route(Ip, Unlimited().ToJsonString()))),
                BlockCondition = TypeIsHosting,
                OnMissingField = MiddlewareOptions<string>.MissingField.Throw,
            },
            request => request);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => core.EvaluateAsync(Ip));

        Assert.Contains("asn.type", failure.Message);
    }

    [Fact]
    public async Task AConditionOnTheAsTypeBlocksWhereTheAnswerCarriesItAndSaysNothing()
    {
        var core = new Core<string>(
            new MiddlewareOptions<string>
            {
                Client = Stub.Client(StubHandler.Lookups(Stub.Route(Ip, Paid().ToJsonString()))),
                BlockCondition = TypeIsHosting,
                OnMissingField = MiddlewareOptions<string>.MissingField.Throw,
            },
            request => request);

        var lookup = await core.EvaluateAsync(Ip);

        Assert.True(lookup!.Blocked);
        Assert.Equal("hosting", lookup.Result!.Asn!.Type);
    }

    // The bot flag is a paid plan's too: a keyless answer has none, so a condition on it is reported
    // by its name and never matched.
    [Fact]
    public async Task AConditionOnTheBotFlagNeverBlocksAnAnswerWithoutItAndIsReportedMissing()
    {
        var body = Unlimited();
        Assert.False(body.ContainsKey("is_bot"));
        var result = await Read("lookup", body);
        var isBot = new[] { new Condition { ["is_bot"] = true } };

        Assert.Null(result.IsBot);
        Assert.Equal(["is_bot"], Condition.MissingMembers(isBot, result));
        Assert.False(Condition.Matches(isBot, result));

        var warnings = new List<string>();
        var core = new Core<string>(
            new MiddlewareOptions<string>
            {
                Client = Stub.Client(StubHandler.Lookups(Stub.Route(Ip, body.ToJsonString()))),
                BlockCondition = isBot,
                OnWarn = warnings.Add,
            },
            request => request);

        Assert.False((await core.EvaluateAsync(Ip))!.Blocked);
        Assert.Contains("is_bot", Assert.Single(warnings));
    }
}
