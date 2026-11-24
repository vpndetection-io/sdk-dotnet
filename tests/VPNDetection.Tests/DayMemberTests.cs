using System.Text.Json.Nodes;
using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// Spec 2026.11.23 gives <c>first_seen</c> and <c>last_seen</c> on the bot, SSH, SMTP, web, DNS
/// resolver and BitTorrent details <c>format: date</c>. They stay strings, and each is read as a
/// calendar day alone, as the <c>DateOnly</c> members are: 6.3.0 handed any string back as served.
/// </summary>
public class DayMemberTests
{
    private const string Web = """
        {"port":80,"tls_ok":false,"session_ok":true,"status_code":301,"server":"cloudflare",
        "location":"https://one.one.one.one/","title":"","cert_subject_cn":"","cert_subject_o":"",
        "cert_issuer_dn":"","cert_browser_trusted":false,"tls_version":"","first_seen":"2026-08-04",
        "last_seen":"2026-11-15"}
        """;

    private static readonly string[] Details = ["bot", "ssh", "smtp", "web", "dns_resolver", "bittorrent"];

    private static readonly string[] Members = ["first_seen", "last_seen"];

    // Every one of the twelve populated, as the API writes them.
    private static JsonObject Answer()
    {
        var answer = new JsonObject { ["ip"] = "45.83.91.1", ["is_vpn"] = false };
        foreach (var detail in Details)
        {
            answer[detail] = detail == "web"
                ? new JsonArray(JsonNode.Parse(Web))
                : new JsonObject { ["first_seen"] = "2026-08-04", ["last_seen"] = "2026-11-15" };
        }
        return answer;
    }

    private static JsonObject With(string detail, string member, string value)
    {
        var answer = Answer();
        var held = detail == "web" ? answer["web"]![0]! : answer[detail]!;
        held[member] = value;
        return answer;
    }

    public static TheoryData<string> NotADay() =>
    [
        "x", "tomorrow", "monday", "2026-02-30", "2026-11-15T24:00", "2026-11-15T10:00:00Z", "2026-11-15+05",
        "2026-11-15\n", "٢026-11-15", "2026-11-1٥",
    ];

    [Theory]
    [MemberData(nameof(NotADay))]
    public async Task ABotsLastSeenThatIsNotADayIsARetriedServerError(string value)
    {
        var body = Answer();
        var handler = new StubHandler(_ => StubHandler.Json(new Route(body.ToJsonString())));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", Retries = 1, CacheEnabled = false });

        var read = await client.LookupAsync("45.83.91.1");
        Assert.Equal("2026-11-15", read.Bot?.LastSeen);
        Assert.Equal("2026-08-04", read.Bot?.FirstSeen);

        body = With("bot", "last_seen", value);
        var failure = await Assert.ThrowsAsync<VpnDetectionException>(() => client.LookupAsync("45.83.91.1"));

        Assert.Equal(ErrorKind.ServerError, failure.Kind);
        Assert.Equal(200, failure.StatusCode);
        Assert.Equal(3, handler.Calls.Count);
    }

    [Fact]
    public async Task EachOfTheTwelveIsReadAsADayAndRefusedOtherwise()
    {
        var body = Answer();
        var handler = new StubHandler(_ => StubHandler.Json(new Route(body.ToJsonString())));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", Retries = 0, CacheEnabled = false });

        var read = await client.LookupAsync("45.83.91.1");
        string?[] days =
        [
            read.Bot?.FirstSeen, read.Bot?.LastSeen, read.Ssh?.FirstSeen, read.Ssh?.LastSeen,
            read.Smtp?.FirstSeen, read.Smtp?.LastSeen, read.Web?[0].FirstSeen, read.Web?[0].LastSeen,
            read.DnsResolver?.FirstSeen, read.DnsResolver?.LastSeen, read.Bittorrent?.FirstSeen, read.Bittorrent?.LastSeen,
        ];
        Assert.Equal(["2026-08-04", "2026-11-15"], days.Chunk(2).SelectMany(pair => pair).Distinct());

        var refused = new List<string>();
        foreach (var detail in Details)
        {
            foreach (var member in Members)
            {
                body = With(detail, member, "x");
                var failure = await Record.ExceptionAsync(() => client.LookupAsync("45.83.91.1"));
                if (failure is VpnDetectionException { Kind: ErrorKind.ServerError, StatusCode: 200 })
                {
                    refused.Add($"{detail}.{member}");
                }
            }
        }
        Assert.Equal(Details.SelectMany(detail => Members.Select(member => $"{detail}.{member}")), refused);
    }
}
