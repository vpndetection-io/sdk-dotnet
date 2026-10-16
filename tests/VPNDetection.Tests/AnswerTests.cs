using System.Globalization;
using System.Net;
using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// What a call does with an answer it cannot read, a <c>Retry-After</c> in a form RFC 9110 does
/// not have, and a key that is blank or holds a control character. Each case here went wrong on
/// 5.4.1 (measured 2026-10-13 against a local origin).
/// </summary>
public class AnswerTests
{
    // 5.4.1 read a 200 it could not parse as a BadRequest, sent once, and `{}` as an answer: a
    // lookup of nulls, an empty plan, an empty catalog. The link's 200 was a ServerError with no
    // status, sent once.
    [Theory]
    [MemberData(nameof(Unreadable))]
    public async Task A200TheCallCannotReadIsARetriedServerErrorWithItsStatus(string call, string body)
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route(body)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 1, CacheEnabled = false });

        var failure = await Failure(client, call);

        Assert.Equal(ErrorKind.ServerError, failure.Kind);
        Assert.Equal(200, failure.StatusCode);
        Assert.Equal(2, handler.Calls.Count);
    }

    public static TheoryData<string, string> Unreadable()
    {
        var data = new TheoryData<string, string>();
        foreach (var call in new[] { "lookup", "myIp", "myEntitlement", "batch", "list", "metadata", "checksums", "downloads", "downloadUrl" })
        {
            foreach (var body in new[] { "<html>gateway</html>", "", "null", "[]", "{}" })
            {
                data.Add(call, body);
            }
        }
        data.Add("batch", """{"results":{}}""");
        data.Add("myEntitlement", """{"org_id":"o","apikey":{"id":"a","expires":null,"allowed_cidrs":[]},"plan":{"key":"k","tier":"t"}}""");
        data.Add("checksums", """{"id":"vpn_ip_v1","format":"mmdb"}""");
        return data;
    }

    // A body that ends short of its Content-Length raised a raw HttpIOException out of the call.
    [Fact]
    public async Task ABodyCutOffIsARetriedNetworkError()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new CutOffContent() });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 1, CacheEnabled = false });

        var failure = await Assert.ThrowsAsync<VpnDetectionException>(() => client.LookupAsync("45.83.91.1"));

        Assert.Equal(ErrorKind.Network, failure.Kind);
        Assert.Equal(2, handler.Calls.Count);
    }

    // Seconds are digits alone and a date is one of RFC 9110's three forms, in GMT. 5.4.1 read `+1`
    // as a second, `1.5`, `Jan 1 2099` and an ISO 8601 time as dates, and a zone-less ISO time in
    // the machine's zone.
    [Theory]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("1_0")]
    [InlineData("0x10")]
    [InlineData("1e3")]
    [InlineData("tomorrow")]
    [InlineData("2099-01-01T00:00:00")]
    [InlineData("2099-01-01T00:00:00Z")]
    [InlineData("Jan 1 2099")]
    [InlineData("Thu, 01 Jan 2099 00:00:00 PST")]
    [InlineData("Thu, 1 Jan 2099 00:00:00 GMT")]
    [InlineData("Mon, 31 Nov 2099 00:00:00 GMT")]
    [InlineData("9223372036854775807")]
    public void ARetryAfterInNeitherFormIsNoWait(string value)
        => Assert.Null(Wire.ParseRetryAfter(value));

    [Theory]
    [InlineData("7", 7)]
    [InlineData(" 7 ", 7)]
    [InlineData("0", 0)]
    public void ARetryAfterInSecondsIsThatWait(string value, int seconds)
        => Assert.Equal(TimeSpan.FromSeconds(seconds), Wire.ParseRetryAfter(value));

    // Each of the three forms, an hour ahead and read as GMT whatever the machine's zone.
    [Theory]
    [InlineData("ddd, dd MMM yyyy HH:mm:ss 'GMT'")]
    [InlineData("dddd, dd-MMM-yy HH:mm:ss 'GMT'")]
    [InlineData("ddd MMM d HH:mm:ss yyyy")]
    public void ARetryAfterDateIsReadAsGmt(string format)
    {
        var at = DateTime.UtcNow.AddHours(1);
        var value = at.ToString(format, CultureInfo.InvariantCulture);
        if (format.StartsWith("ddd MMM d ", StringComparison.Ordinal) && at.Day < 10)
        {
            value = value.Replace($" {at.Day} ", $"  {at.Day} ", StringComparison.Ordinal);
        }

        var wait = Wire.ParseRetryAfter(value);

        Assert.NotNull(wait);
        Assert.InRange(wait!.Value, TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(61));
    }

    // 5.4.1 sent a blank key as `Bearer` and the blank, a padded one padded, and put a key's CR LF
    // on the wire, where it wrote a header of its own.
    [Theory]
    [InlineData(" ", null)]
    [InlineData("\t", null)]
    [InlineData("  k  ", "Bearer k")]
    [InlineData("k\n", "Bearer k")]
    public async Task TheKeyIsTrimmedAndABlankOneIsNoKey(string key, string? expected)
    {
        HttpRequestMessage? sent = null;
        var handler = new StubHandler(request =>
        {
            sent = request;
            return StubHandler.Json(new Route(Stub.LookupBody("45.83.91.1")));
        });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = key });

        await client.LookupAsync("45.83.91.1");

        Assert.Equal(expected, sent!.Headers.TryGetValues("Authorization", out var values) ? values.Single() : null);
    }

    [Theory]
    [InlineData("secret\r\nX-Injected: 1")]
    [InlineData("secret\0")]
    [InlineData("secret\u007f")]
    [InlineData("sec\tret")]
    [InlineData("sec\u0085ret")]
    // Accepted through 5.4.3, and every call failed as a retried Network error with nothing sent:
    // SocketsHttpHandler sends a header value as ASCII alone.
    [InlineData("sec\u00e9ret")]
    [InlineData("sec\u4e2dret")]
    public void AKeyHoldingAControlCharacterOrOneOutsideAsciiIsRefusedWhereItIsSet(string key)
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route("{}")));

        var refused = Assert.Throws<ArgumentException>(() => Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = key }));

        Assert.Contains("control character or one outside ASCII", refused.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("sec", refused.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Calls);
    }

    private static async Task<VpnDetectionException> Failure(VpnDetectionClient client, string call)
    {
        if (call == "batch")
        {
            var answers = await client.LookupBatchAsync(new[] { "45.83.91.1", "45.83.91.2" });
            Assert.All(answers.Values, a => Assert.False(a.IsSuccess));
            return answers["45.83.91.2"].Error!;
        }
        return await Assert.ThrowsAsync<VpnDetectionException>(() => call switch
        {
            "lookup" => client.LookupAsync("45.83.91.1"),
            "myIp" => client.MyIpAsync(),
            "myEntitlement" => client.MyEntitlementAsync(),
            "list" => client.Database.ListAsync(),
            "metadata" => client.Database.MetadataAsync("vpn_ip_v1"),
            "checksums" => client.Database.ChecksumsAsync("vpn_ip_v1", DatabaseFormat.Mmdb),
            "downloads" => client.Database.DownloadsAsync(),
            _ => (Task)client.Database.DownloadUrlAsync("vpn_ip_v1", DatabaseFormat.Mmdb),
        });
    }

    // Ten bytes of a body that promised more, then the end of the connection.
    private sealed class CutOffContent : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await stream.WriteAsync("{\"ip\":\"45."u8.ToArray());
            throw new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely.");
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 400;
            return true;
        }
    }
}
