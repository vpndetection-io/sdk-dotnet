using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// An answer holds what the spec says, in the form it says. 5.10.1 read an enum from a number, a
/// numeric string or any case (from 6.0.0 a vocabulary is any string, as served), kept a sample row that is not an object, took a date-time with a
/// trailing newline, failed with a raw <c>FormatException</c> on a digit from another script, and
/// refused a fraction past nine digits and an offset past 14 hours, both RFC 3339 (measured
/// 2026-10-29).
/// </summary>
public class AnswerFormTests
{
    private const string Family = """
        {"base":"vpn_ip_extended","name":"VPN IP Extended","summary":"s","starts":"2026-01-01T00:00:00Z",
        "expires":null,"renews_at":null,"notice_due_at":null,"license_type":"standard","in_term":true,"open":false,
        "standing":"licensed","versions":[{"id":"vpn_ip_extended_v1","version":1,
        "formats":[{"format":"mmdb","bytes":1234}],"sample_formats":["csvgz"]}]}
        """;

    private const string Attempt = """
        {"dataset_id":"vpn_ip_extended_v1","format":"mmdb","outcome":"ok","sample":false,"open":false,
        "bytes":1234,"created":"2026-09-04T10:00:00Z"}
        """;

    private const string Entitlement = """
        {"org_id":"85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61","apikey":{"id":"0ab424cc-7619-4dad-b027-afacdc2cedb0",
        "expires":null,"allowed_cidrs":[]},"plan":{"key":"max","name":"Max","tier":"max"},"usage":{"requests":5,"quota":50,
        "hard_limit":null,"window_start":"2026-10-04T06:00:00Z","window_end":"2026-10-04T07:00:00Z"}}
        """;

    private const string Metadata = """
        {"id":"vpn_ip_extended_v1","update_freq":"daily","updated":"2026-09-04","entries":42,
        "schema":{"mmdb":[{"name":"ip","type":"string"}]},"sample":{"mmdb":[{"ip":"45.83.91.0/24"}]}}
        """;

    private const string Lookup = """{"ip":"45.83.91.1","is_vpn":true,"vpn":{"provider":"p","last_seen":"2026-09-04"}}""";

    public static TheoryData<string, string> NotTheSpecsAnswer()
    {
        var data = new TheoryData<string, string>();
        string[] dateTimes =
        [
            "2026-10-05T10:00:00Z\n", "2026-10-05T10:00:00+05:30\n", "٢026-10-05T10:00:00Z",
            "2026-10-05T1٠:00:00Z", "2026-10-05T10:00:00.١Z", "2026-10-05T10:00:00+05:3٠",
            "2026-10-05T10:00:00Ｚ",
        ];
        foreach (var value in dateTimes)
        {
            data.Add("list", Wrap("databases", Family, "starts", value));
            data.Add("downloads", Wrap("downloads", Attempt, "created", value));
            data.Add("myEntitlement", Set(Entitlement, ["usage", "window_start"], value));
        }
        foreach (var value in new[] { "2026-10-05\n", "٢026-10-05", "2026-10-0٥" })
        {
            data.Add("metadata", Set(Metadata, ["updated"], value));
            data.Add("lookup", Set(Lookup, ["vpn", "last_seen"], value));
        }
        // A vocabulary member is any string the API serves; a number, a list, an object, or a null
        // where the spec requires one, is not an answer.
        JsonNode?[] notAString = [0, null, new JsonArray("licensed"), new JsonObject { ["value"] = "licensed" }];
        foreach (var value in notAString)
        {
            data.Add("list", Wrap("databases", Family, "standing", value?.DeepClone()));
            data.Add("downloads", Wrap("downloads", Attempt, "outcome", value?.DeepClone()));
            data.Add("myEntitlement", Set(Entitlement, ["plan", "tier"], value?.DeepClone()));
        }
        data.Add("list", Wrap("databases", Family, "license_type", 1));
        data.Add("list", Wrap("databases", Family.Replace("\"format\":\"mmdb\"", "\"format\":0", StringComparison.Ordinal), "open", false));
        data.Add("list", Wrap("databases", Family.Replace("\"format\":\"mmdb\"", "\"format\":null", StringComparison.Ordinal), "open", false));
        data.Add("list", Wrap("databases", Family.Replace("[\"csvgz\"]", "[0]", StringComparison.Ordinal), "open", false));
        data.Add("list", Wrap("databases", Family.Replace("[\"csvgz\"]", "[null]", StringComparison.Ordinal), "open", false));
        foreach (var row in new[] { "null", "1", "\"x\"", "[]" })
        {
            data.Add("metadata", Metadata.Replace("[{\"ip\":\"45.83.91.0/24\"}]", "[" + row + "]", StringComparison.Ordinal));
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(NotTheSpecsAnswer))]
    public async Task AnAnswerTheSpecDoesNotAllowIsARetriedServerError(string call, string body)
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route(body)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", Retries = 1, CacheEnabled = false });

        var failure = await Assert.ThrowsAsync<VpnDetectionException>(() => Call(client, call));

        Assert.Equal(ErrorKind.ServerError, failure.Kind);
        Assert.Equal(200, failure.StatusCode);
        Assert.Equal(2, handler.Calls.Count);
    }

    [Theory]
    [InlineData("2026-10-05T10:00:00.1234567890123Z", "2026-10-05T10:00:00.1234567+00:00")]
    [InlineData("2024-02-29T23:59:59+14:00", "2024-02-29T23:59:59.0000000+14:00")]
    [InlineData("2024-02-29T23:59:59+14:01", "2024-02-29T09:58:59.0000000+00:00")]
    [InlineData("2024-02-29T23:59:59-23:59", "2024-03-01T23:58:59.0000000+00:00")]
    [InlineData("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.0000000+00:00")]
    public async Task ADateTimeInAnyRfc3339SpellingStaysAnAnswer(string value, string expected)
    {
        using var listing = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Wrap("databases", Family, "starts", value)))));
        using var history = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Wrap("downloads", Attempt, "created", value)))));
        using var plan = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Set(Entitlement, ["usage", "window_start"], value)))));

        var read = new[]
        {
            (await listing.Database.ListAsync())[0].Starts!.Value,
            (await history.Database.DownloadsAsync())[0].Created,
            (await plan.MyEntitlementAsync()).Usage.WindowStart,
        };

        Assert.All(read, date => Assert.Equal(expected, date.ToString("o", CultureInfo.InvariantCulture)));
    }

    [Fact]
    public async Task EveryEnumStillReadsByItsWireName()
    {
        var family = JsonNode.Parse(Family)!;
        family["license_type"] = null;
        family["standing"] = "unlicensed";
        using var listing = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(new JsonObject { ["databases"] = new JsonArray(family) }.ToJsonString()))));
        using var history = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Wrap("downloads", Attempt, "outcome", "unavailable")))));
        using var plan = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Set(Entitlement, ["plan", "tier"], "scale")))));
        using var catalog = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Metadata))));

        var database = (await listing.Database.ListAsync())[0];
        var attempt = (await history.Database.DownloadsAsync())[0];
        var tier = (await plan.MyEntitlementAsync()).Plan.Tier;
        var sample = (await catalog.Database.MetadataAsync("vpn_ip_extended_v1")).Sample!["mmdb"].Single();

        Assert.Equal(Standing.Unlicensed, database.Standing);
        Assert.Null(database.LicenseType);
        var version = database.Versions.Single();
        Assert.Equal(DatabaseFormat.Mmdb, version.Formats.Single().Format);
        Assert.Equal(new[] { DatabaseFormat.Csvgz }, version.SampleFormats);
        Assert.Equal(DownloadOutcome.Unavailable, attempt.Outcome);
        Assert.Equal(EntitlementPlanTier.Scale, tier);
        Assert.Equal("45.83.91.0/24", ((JsonElement)sample).GetProperty("ip").GetString());
    }

    // 5.15.0 read a vocabulary as a closed enum, so a value the API added failed the call, and
    // 5.10.1 read one in any case or from a numeric string. Each string comes back as served,
    // equal to no known value unless it is one exactly.
    [Theory]
    [InlineData("suspended")]
    [InlineData("LICENSED")]
    [InlineData("Licensed")]
    [InlineData("0")]
    [InlineData("")]
    public async Task AVocabularyValueReadsAsServed(string value)
    {
        var family = JsonNode.Parse(Family)!;
        family["standing"] = value;
        family["license_type"] = value;
        family["versions"]![0]!["formats"]![0]!["format"] = value;
        family["versions"]![0]!["sample_formats"] = new JsonArray(value, "csvgz");
        using var listing = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(new JsonObject { ["databases"] = new JsonArray(family) }.ToJsonString()))));
        using var history = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Wrap("downloads", Attempt, "outcome", value)))));
        using var plan = Stub.Client(new StubHandler(_ => StubHandler.Json(new Route(Set(Entitlement, ["plan", "tier"], value)))));

        var database = (await listing.Database.ListAsync())[0];
        var outcome = (await history.Database.DownloadsAsync())[0].Outcome;
        var tier = (await plan.MyEntitlementAsync()).Plan.Tier;
        var version = database.Versions.Single();

        Assert.Equal(value, database.Standing.Value);
        Assert.False(database.Standing.IsKnown);
        Assert.Equal(new Standing(value), database.Standing);
        Assert.NotEqual(Standing.Licensed, database.Standing);
        Assert.Equal(value, database.LicenseType!.Value);
        Assert.False(database.LicenseType.IsKnown);
        Assert.Equal(value, version.Formats.Single().Format.Value);
        Assert.Equal(new[] { new DatabaseFormat(value), DatabaseFormat.Csvgz }, version.SampleFormats);
        Assert.Equal(value, outcome.Value);
        Assert.False(outcome.IsKnown);
        Assert.Equal(value, tier.Value);
        Assert.False(tier.IsKnown);
    }

    [Fact]
    public void AVocabularyComparesByValueAndListsWhatThisReleaseKnows()
    {
        Assert.True(new Standing("licensed") == Standing.Licensed);
        Assert.True(new Standing("licensed").IsKnown);
        Assert.Equal(Standing.Licensed.GetHashCode(), new Standing("licensed").GetHashCode());
        Assert.True(new Standing("LICENSED") != Standing.Licensed);
        Assert.Equal("licensed", Standing.Licensed.ToString());
        Assert.Equal(["expired", "licensed", "unlicensed"], Standing.Known.Select(known => known.Value));
        Assert.Equal(["csvgz", "mmdb"], DatabaseFormat.Known.Select(known => known.Value));
        Assert.Equal(["evaluation", "standard", "redistribute"], DatabaseLicense_type.Known.Select(known => known.Value));
        Assert.Equal(["ok", "unauthorized", "denied", "expired", "unknown", "unavailable"], DownloadOutcome.Known.Select(known => known.Value));
        Assert.Equal(["free", "starter", "scale", "max"], EntitlementPlanTier.Known.Select(known => known.Value));
        Assert.Throws<ArgumentNullException>(() => new Standing(null!));
    }

    private static string Wrap(string envelope, string entry, string member, JsonNode? value)
        => new JsonObject { [envelope] = new JsonArray(Set(JsonNode.Parse(entry)!, [member], value)) }.ToJsonString();

    private static string Set(string body, string[] path, JsonNode? value) => Set(JsonNode.Parse(body)!, path, value).ToJsonString();

    private static JsonNode Set(JsonNode node, string[] path, JsonNode? value)
    {
        var parent = node;
        foreach (var step in path[..^1])
        {
            parent = parent[step]!;
        }
        parent[path[^1]] = value;
        return node;
    }

    private static Task Call(VpnDetectionClient client, string call) => call switch
    {
        "list" => client.Database.ListAsync(),
        "downloads" => client.Database.DownloadsAsync(),
        "myEntitlement" => client.MyEntitlementAsync(),
        "metadata" => client.Database.MetadataAsync("vpn_ip_extended_v1"),
        _ => client.LookupAsync("45.83.91.1"),
    };
}
