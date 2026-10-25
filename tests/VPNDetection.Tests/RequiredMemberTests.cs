using System.Reflection;
using System.Text.Json.Serialization;
using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// A member the spec requires and never sends as null, served null, and a null inside a list or
/// map. Each case here came back as the answer on 5.9.0 (measured 2026-10-25 against a stub).
/// </summary>
public class RequiredMemberTests
{
    private const string Lookup = """{"ip":"45.83.91.1","is_vpn":true,"pubproxy":{"entry":true,"num_ports":2,"protocols":["http"]},"location":{"continent":"EU","continent_name":"Europe","country":"AT","country_name":"Austria","timezone":"Europe/Vienna","currency_code":"EUR","currency_name":"Euro","currency_symbol":"€","flag_emoji":"x","flag_unicode":"x"},"asn":{"asn":9009,"name":"M247 Europe SRL","domain":"m247global.com","type":"hosting","prefix":"146.70.116.0/24"}}""";
    private const string Entitlement = """{"org_id":"85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61","apikey":{"id":"0ab424cc-7619-4dad-b027-afacdc2cedb0","expires":null,"allowed_cidrs":[]},"plan":{"key":"max","tier":"max"},"usage":{"requests":5,"quota":50,"hard_limit":null,"window_start":"2026-10-04T07:00:00Z","window_end":"2026-11-04T07:00:00Z"}}""";
    private const string List = """{"databases":[{"base":"vpn_ip_extended","name":"VPN IP Extended","summary":"s","starts":null,"expires":null,"renews_at":null,"notice_due_at":null,"license_type":"standard","in_term":true,"open":false,"standing":"licensed","versions":[{"id":"vpn_ip_extended_v1","version":1,"formats":[{"format":"mmdb","bytes":1234}],"sample_formats":["csvgz"]}]}]}""";
    private const string Metadata = """{"id":"vpn_ip_extended_v1","update_freq":"daily","updated":"2026-10-05","entries":42,"size":{"mmdb":760},"schema":{"mmdb":[{"name":"ip","type":"string"}]}}""";
    private const string Downloads = """{"downloads":[{"dataset_id":"vpn_ip_extended_v1","format":"mmdb","outcome":"ok","sample":false,"open":false,"bytes":null,"created":"2026-09-02T10:00:00Z"}]}""";
    private const string Checksums = """{"id":"vpn_ip_extended_v1","format":"mmdb","checksums":{"md5":"m","sha1":"s1","sha256":"s256","sha512":"s512"}}""";

    public static TheoryData<string, string, string> Nulls() => new()
    {
        { "lookup", "\"country\":\"AT\"", "\"country\":null" },
        { "lookup", "\"name\":\"M247 Europe SRL\"", "\"name\":null" },
        { "lookup", "[\"http\"]", "[null]" },
        { "batch", "\"country\":\"AT\"", "\"country\":null" },
        { "myEntitlement", "\"key\":\"max\"", "\"key\":null" },
        { "myEntitlement", "\"allowed_cidrs\":[]", "\"allowed_cidrs\":null" },
        { "myEntitlement", "\"allowed_cidrs\":[]", "\"allowed_cidrs\":[null]" },
        { "list", "\"name\":\"VPN IP Extended\"", "\"name\":null" },
        { "list", "\"summary\":\"s\"", "\"summary\":null" },
        { "list", "\"standing\":\"licensed\"", "\"standing\":null" },
        { "list", "\"id\":\"vpn_ip_extended_v1\"", "\"id\":null" },
        { "list", "[{\"format\":\"mmdb\",\"bytes\":1234}]", "null" },
        { "list", "[{\"format\":\"mmdb\",\"bytes\":1234}]", "[null]" },
        { "list", "\"open\":false,", "" },
        { "metadata", "\"schema\":{\"mmdb\":[{\"name\":\"ip\",\"type\":\"string\"}]}", "\"schema\":null" },
        { "metadata", "\"name\":\"ip\"", "\"name\":null" },
        { "metadata", "[{\"name\":\"ip\",\"type\":\"string\"}]", "[null]" },
        { "metadata", "\"entries\":42,", "" },
        { "downloads", "\"dataset_id\":\"vpn_ip_extended_v1\"", "\"dataset_id\":null" },
        { "downloads", "\"outcome\":\"ok\"", "\"outcome\":null" },
        { "downloads", "\"sample\":false,", "" },
        { "checksums", "\"id\":\"vpn_ip_extended_v1\",", "" },
        { "checksums", "\"format\":\"mmdb\",", "" },
    };

    [Theory]
    [MemberData(nameof(Nulls))]
    public async Task AMemberTheSpecDoesNotAllowNullOrAbsentIsARetriedServerError(string call, string from, string to)
    {
        var body = Body(call);
        Assert.Contains(from, body, StringComparison.Ordinal);
        var served = body.Replace(from, to, StringComparison.Ordinal);
        var handler = new StubHandler(_ => StubHandler.Json(new Route(call == "batch" ? Batch(served) : served)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", Retries = 1, CacheEnabled = false });

        var failure = await Call(client, call);

        Assert.Equal(ErrorKind.ServerError, failure.Kind);
        Assert.Equal(200, failure.StatusCode);
        Assert.Equal(2, handler.Calls.Count);
    }

    // The same bodies, whole, are answers: what the spec lets be null or absent still reads.
    [Theory]
    [InlineData("lookup")]
    [InlineData("batch")]
    [InlineData("myEntitlement")]
    [InlineData("list")]
    [InlineData("metadata")]
    [InlineData("downloads")]
    [InlineData("checksums")]
    public async Task EachBodyWholeIsAnAnswer(string call)
    {
        var body = Body(call);
        var handler = new StubHandler(_ => StubHandler.Json(new Route(call == "batch" ? Batch(body) : body)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", CacheEnabled = false });

        await Answer(client, call);

        Assert.Single(handler.Calls);
    }

    // The table is the spec's `required` lists less what each marks nullable, and NSwag writes
    // exactly those members as non-nullable properties, so a re-pin that adds one turns this red
    // until the table has it. Every class an answer reaches that requires a member must be in the
    // table, bar the two envelopes matched by their one member.
    [Fact]
    public void TheRequiredMembersAreTheGeneratedTypesNonNullableOnes()
    {
        var nullability = new NullabilityInfoContext();
        var seen = new HashSet<Type>();
        var pending = new Stack<Type>(
        [
            typeof(Response), typeof(Response2), typeof(Response3), typeof(DatabaseMetadata),
            typeof(LookupResponse), typeof(BatchLookupResponse), typeof(Entitlement),
        ]);
        while (pending.TryPop(out var type))
        {
            if (!seen.Add(type))
            {
                continue;
            }
            var members = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var property in type.GetProperties())
            {
                var name = property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name;
                if (name is null)
                {
                    continue;
                }
                var required = property.PropertyType.IsValueType
                    ? Nullable.GetUnderlyingType(property.PropertyType) is null
                    : nullability.Create(property).ReadState == NullabilityState.NotNull;
                if (required)
                {
                    members.Add(name);
                }
                foreach (var reached in Reached(property.PropertyType))
                {
                    pending.Push(reached);
                }
            }
            if (type == typeof(Response) || type == typeof(Response3))
            {
                Assert.Subset(WireClient.EnvelopeMembers, members.ToHashSet());
                continue;
            }
            // A detail object requires nothing: it is `{}` where its flag is false.
            var table = WireClient.AnswerMembers.TryGetValue(type, out var named) ? named : [];
            Assert.Equal(members, new SortedSet<string>(table, StringComparer.Ordinal));
        }
        Assert.Subset(seen, WireClient.AnswerMembers.Keys.ToHashSet());
    }

    private static IEnumerable<Type> Reached(Type type)
    {
        if (type.Assembly == typeof(VpnDetectionClient).Assembly && type.IsClass)
        {
            yield return type;
        }
        foreach (var argument in type.GetGenericArguments())
        {
            foreach (var reached in Reached(argument))
            {
                yield return reached;
            }
        }
    }

    private static string Body(string call) => call switch
    {
        "lookup" or "batch" => Lookup,
        "myEntitlement" => Entitlement,
        "list" => List,
        "metadata" => Metadata,
        "downloads" => Downloads,
        _ => Checksums,
    };

    private static string Batch(string entry) => "{\"results\":{\"45.83.91.1\":" + entry + "},\"errors\":{}}";

    private static async Task<VpnDetectionException> Call(VpnDetectionClient client, string call)
    {
        if (call == "batch")
        {
            var answers = await client.LookupBatchAsync(new[] { "45.83.91.1" });
            return answers["45.83.91.1"].Error ?? throw new Xunit.Sdk.XunitException("the batch entry was answered");
        }
        return await Assert.ThrowsAsync<VpnDetectionException>(() => Answer(client, call));
    }

    private static async Task Answer(VpnDetectionClient client, string call)
    {
        switch (call)
        {
            case "lookup":
                await client.LookupAsync("45.83.91.1");
                break;
            case "batch":
                Assert.True((await client.LookupBatchAsync(new[] { "45.83.91.1" }))["45.83.91.1"].IsSuccess);
                break;
            case "myEntitlement":
                await client.MyEntitlementAsync();
                break;
            case "list":
                await client.Database.ListAsync();
                break;
            case "metadata":
                await client.Database.MetadataAsync("vpn_ip_extended_v1");
                break;
            case "downloads":
                await client.Database.DownloadsAsync();
                break;
            default:
                await client.Database.ChecksumsAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);
                break;
        }
    }
}
