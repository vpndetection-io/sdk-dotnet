using System.Net;

using Xunit;

namespace VPNDetection.Tests;

// The database responses nest their payload, and an unwrap at the wrong depth returns nothing
// against a perfectly healthy API. The Node SDK shipped exactly that in 1.0.x: `checksums` read a
// top-level `sha256` that is not there.
public class DatabaseTests
{
    private static readonly Dictionary<string, string> Bodies = new()
    {
        ["/api/v1/database/list"] = """
            {"datasets":[{"id":"vpn_ip_extended_v1","name":"VPN IP Extended","redistribution":"internal",
            "in_term":true,"formats":[{"format":"mmdb","bytes":1234},{"format":"csvgz","bytes":null}]}]}
            """,
        ["/api/v1/database/checksum"] = """
            {"id":"vpn_ip_extended_v1","format":"mmdb",
            "checksums":{"md5":"m","sha1":"s1","sha256":"s256","sha512":"s512"}}
            """,
        ["/api/v1/database/downloads"] = """
            {"downloads":[{"dataset_id":"vpn_ip_extended_v1","format":"mmdb","outcome":"ok",
            "bytes":1234,"created":"2026-09-02T10:00:00Z"}]}
            """,
        ["/api/v1/database/metadata"] = """
            {"id":"vpn_ip_extended_v1","update_freq":"daily","updated":"2026-09-02","entries":42,
            "schema":{"mmdb":[{"name":"ip","type":"string"}]}}
            """,
    };

    [Fact]
    public async Task ResponsesAreUnwrappedAtTheRightDepth()
    {
        var handler = new StubHandler(request =>
            StubHandler.Json(new Route(Bodies[request.RequestUri!.AbsolutePath])));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k" });

        var sums = await client.Database.ChecksumsAsync("vpn_ip_extended_v1", DatasetFormat.Mmdb);
        Assert.Equal("m", sums.Md5);
        Assert.Equal("s1", sums.Sha1);
        // The digest a caller actually wants must not be null.
        Assert.Equal("s256", sums.Sha256);
        Assert.Equal("s512", sums.Sha512);

        var datasets = await client.Database.ListAsync();
        Assert.Equal("vpn_ip_extended_v1", Assert.Single(datasets).Id);
        Assert.True(datasets[0].InTerm);
        Assert.Equal(DatasetRedistribution.Internal, datasets[0].Redistribution);
        Assert.Equal(DatasetFormat.Mmdb, datasets[0].Formats[0].Format);
        // `bytes: null` is a published-yet-unbuilt format, not a missing key.
        Assert.Null(datasets[0].Formats[1].Bytes);

        var downloads = await client.Database.DownloadsAsync();
        Assert.Equal("vpn_ip_extended_v1", Assert.Single(downloads).DatasetId);
        Assert.Equal(DownloadOutcome.Ok, downloads[0].Outcome);

        var metadata = await client.Database.MetadataAsync("vpn_ip_extended_v1");
        Assert.Equal("vpn_ip_extended_v1", metadata.Id);
        Assert.Equal(new DateOnly(2026, 9, 2), metadata.Updated);
        Assert.Equal("daily", metadata.UpdateFreq);
    }

    [Fact]
    public async Task TheFormatArgumentIsSentAsItsWireValueNotItsOrdinal()
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route(Bodies["/api/v1/database/checksum"])));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k" });

        await client.Database.ChecksumsAsync("vpn_ip_extended_v1", DatasetFormat.Mmdb);

        Assert.Contains("format=mmdb", handler.Calls[0]);
    }

    [Fact]
    public async Task DownloadUrlReturnsTheLocationOffThe302()
    {
        var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("https://s3.example.test/vpn_ip_extended_v1.mmdb?sig=abc");
            return response;
        });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k" });

        var url = await client.Database.DownloadUrlAsync("vpn_ip_extended_v1", DatasetFormat.Mmdb);

        Assert.Equal("https://s3.example.test/vpn_ip_extended_v1.mmdb?sig=abc", url);
    }

    [Fact]
    public async Task AnUnknownDatasetIsNotRetried()
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route("""{"rc":"NOT_FOUND"}""", 404)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", Retries = 2 });

        var error = await Assert.ThrowsAsync<VpnDetectionException>(
            () => client.Database.MetadataAsync("nope"));

        Assert.Equal(ErrorKind.BadRequest, error.Kind);
        Assert.False(error.Retryable);
        Assert.Equal("NOT_FOUND", error.Message);
        Assert.Single(handler.Calls);
    }

    // .NET's HttpClient follows redirects by DEFAULT, unlike the JDK's, so a borrowed one is the
    // dangerous case: the download endpoint's 302 would be chased and the whole dataset read into
    // memory. The storage origin here promises a gigabyte and sends one byte, so a client that
    // reads the body hangs rather than merely being slow, and the timeout below is the assertion.
    [Fact]
    public async Task AFollowedRedirectIsRefusedBeforeTheBodyIsRead()
    {
        using var origin = new RedirectingServer();
        using var following = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true });
        using var client = new VpnDetectionClient(
            following, new VpnDetectionClientOptions { BaseUrl = origin.BaseUrl, ApiKey = "k" });

        var call = client.Database.DownloadUrlAsync("vpn_ip_extended_v1", DatasetFormat.Mmdb);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => call.WaitAsync(TimeSpan.FromSeconds(15)));

        Assert.Contains("AllowAutoRedirect", error.Message, StringComparison.Ordinal);
        Assert.True(origin.StorageWasAsked, "the redirect was followed, which is the case under test");
    }

    [Fact]
    public async Task ANonFollowingClientGetsTheLinkAndNeverAsksStorage()
    {
        using var origin = new RedirectingServer();
        using var client = new VpnDetectionClient(new VpnDetectionClientOptions { BaseUrl = origin.BaseUrl });

        var url = await client.Database.DownloadUrlAsync("vpn_ip_extended_v1", DatasetFormat.Mmdb);

        Assert.Equal(origin.PayloadUrl, url);
        Assert.False(origin.StorageWasAsked);
    }
}

// A real HTTP origin that answers the download endpoint with a 302 to a SECOND origin, so "the
// client followed the redirect" is observable rather than assumed. Two origins, because that is
// what production does: the API redirects to object storage on another host.
//
// Storage answers with a gigabyte of Content-Length and one byte of body, and never closes the
// response, so anything that tries to READ that body blocks forever.
internal sealed class RedirectingServer : IDisposable
{
    private readonly HttpListener api = new();
    private readonly HttpListener storage = new();

    internal RedirectingServer()
    {
        BaseUrl = $"http://127.0.0.1:{FreePort()}";
        PayloadUrl = $"http://127.0.0.1:{FreePort()}/dataset.mmdb";
        api.Prefixes.Add($"{BaseUrl}/");
        storage.Prefixes.Add($"{new Uri(PayloadUrl).GetLeftPart(UriPartial.Authority)}/");
        api.Start();
        storage.Start();
        _ = Task.Run(() => ServeAsync(api, Redirect));
        _ = Task.Run(() => ServeAsync(storage, StallForever));
    }

    internal string BaseUrl { get; }

    internal string PayloadUrl { get; }

    internal bool StorageWasAsked { get; private set; }

    public void Dispose()
    {
        ((IDisposable)api).Dispose();
        ((IDisposable)storage).Dispose();
    }

    private bool Redirect(HttpListenerContext context)
    {
        context.Response.StatusCode = 302;
        context.Response.RedirectLocation = PayloadUrl;
        return true;
    }

    private bool StallForever(HttpListenerContext context)
    {
        StorageWasAsked = true;
        context.Response.StatusCode = 200;
        context.Response.ContentLength64 = 1_000_000_000;
        context.Response.OutputStream.WriteByte((byte)'x');
        context.Response.OutputStream.Flush();
        return false;
    }

    private static async Task ServeAsync(HttpListener listener, Func<HttpListenerContext, bool> handle)
    {
        while (listener.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync();
            }
            catch (Exception)
            {
                return;
            }
            if (handle(context))
            {
                context.Response.Close();
            }
        }
    }

    private static int FreePort()
    {
        var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }
}
