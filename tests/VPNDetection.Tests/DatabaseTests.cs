using System.Net;
using System.Net.Sockets;
using System.Text;

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
            {"databases":[{"base":"vpn_ip_extended","name":"VPN IP Extended","summary":"vpn_ip rows","starts":"2026-01-01T00:00:00.000Z","expires":null,"renews_at":null,"notice_due_at":null,"license_type":"standard",
            "in_term":true,"standing":"licensed","versions":[{"id":"vpn_ip_extended_v1","version":1,
            "formats":[{"format":"mmdb","bytes":1234},{"format":"csvgz","bytes":null}],
            "sample_formats":["csvgz","mmdb"]}]}]}
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

        var sums = await client.Database.ChecksumsAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);
        Assert.Equal("m", sums.Md5);
        Assert.Equal("s1", sums.Sha1);
        // The digest a caller actually wants must not be null.
        Assert.Equal("s256", sums.Sha256);
        Assert.Equal("s512", sums.Sha512);

        // A licence is held against the FAMILY, and the ids the download and checksum calls take
        // hang off its versions. The spec used to claim `{id, formats}` here, which decoded into a
        // dataset whose every field was empty and left ListAsync unable to say what to download.
        var databases = await client.Database.ListAsync();
        var family = Assert.Single(databases);
        Assert.Equal("vpn_ip_extended", family.Base);
        Assert.True(family.InTerm);
        Assert.Equal(Standing.Licensed, family.Standing);
        Assert.Equal(DatabaseLicense_type.Standard, family.LicenseType);
        var published = Assert.Single(family.Versions);
        Assert.Equal("vpn_ip_extended_v1", published.Id);
        Assert.Equal(1, published.Version);
        Assert.Equal(DatabaseFormat.Mmdb, published.Formats[0].Format);
        // `bytes: null` is a published-yet-unbuilt format, not a missing key.
        Assert.Null(published.Formats[1].Bytes);
        // An enum inside a LIST is the one place NSwag writes no converter, and System.Text.Json
        // reads an enum as a number by default, so a healthy answer throws without the converter
        // Wire.cs registers.
        Assert.Equal(new[] { DatabaseFormat.Csvgz, DatabaseFormat.Mmdb }, published.SampleFormats);

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

        await client.Database.ChecksumsAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);

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

        var url = await client.Database.DownloadUrlAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);

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

        var call = client.Database.DownloadUrlAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);
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

        var url = await client.Database.DownloadUrlAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);

        Assert.Equal(origin.PayloadUrl, url);
        Assert.False(origin.StorageWasAsked);
    }

    // The presigned URL authorizes itself, so the request that follows the 302 must carry no
    // credential: forwarding the API key would hand it to a host with no business holding it.
    [Fact]
    public async Task DownloadStreamsToDiskAndShowsStorageNoCredential()
    {
        var payload = Payload();
        using var origin = new RedirectingServer(payload, truncate: false);
        using var client = new VpnDetectionClient(
            new VpnDetectionClientOptions { BaseUrl = origin.BaseUrl, ApiKey = "k" });
        var path = Path.Combine(TempDir(), "dataset.mmdb");

        var written = await client.Database.DownloadAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb, path);

        Assert.Equal(payload.Length, written);
        Assert.Equal(payload, await File.ReadAllBytesAsync(path));
        Assert.False(File.Exists(path + ".part"), "the .part file outlived a successful transfer");
        Assert.Equal(1, origin.StorageRequests);
        Assert.Null(origin.StorageAuthorization);
    }

    [Fact]
    public async Task DownloadBytesAgreesWithTheStreamedCopy()
    {
        var payload = Payload();
        using var origin = new RedirectingServer(payload, truncate: false);
        using var client = new VpnDetectionClient(
            new VpnDetectionClientOptions { BaseUrl = origin.BaseUrl, ApiKey = "k" });
        var path = Path.Combine(TempDir(), "dataset.mmdb");
        await client.Database.DownloadAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb, path);

        var bytes = await client.Database.DownloadBytesAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb);

        Assert.Equal(await File.ReadAllBytesAsync(path), bytes);
        Assert.Null(origin.StorageAuthorization);
    }

    // A transfer that ends short of its declared length must fail rather than leave a file that
    // reads as a whole dataset. HttpClient raises this for itself, which PHP's streams do not, so
    // what is pinned here is that the failure surfaces AND that nothing survives it.
    [Fact]
    public async Task ATruncatedTransferFailsAndLeavesNothingBehind()
    {
        var payload = Payload();
        using var origin = new RedirectingServer(payload, truncate: true);
        using var client = new VpnDetectionClient(
            new VpnDetectionClientOptions { BaseUrl = origin.BaseUrl, ApiKey = "k" });
        var path = Path.Combine(TempDir(), "dataset.mmdb");

        await Assert.ThrowsAnyAsync<IOException>(
            () => client.Database.DownloadAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb, path));

        Assert.False(File.Exists(path), "a short transfer left a file that reads as a whole dataset");
        Assert.False(File.Exists(path + ".part"), "the .part file outlived a failed transfer");
    }

    [Fact]
    public async Task DownloadBytesRefusesATruncatedTransfer()
    {
        var payload = Payload();
        using var origin = new RedirectingServer(payload, truncate: true);
        using var client = new VpnDetectionClient(
            new VpnDetectionClientOptions { BaseUrl = origin.BaseUrl, ApiKey = "k" });

        await Assert.ThrowsAnyAsync<IOException>(
            () => client.Database.DownloadBytesAsync("vpn_ip_extended_v1", DatabaseFormat.Mmdb));
    }

    // A dataset the organization does not license is refused by the API before any transfer starts,
    // and `rc` is what says WHICH refusal it is. Not retryable: retrying a licence decision two
    // more times helps nobody.
    [Fact]
    public async Task AnUnlicensedDatasetIsRefusedOnceAndCarriesTheApiReasonCode()
    {
        var handler = new StubHandler(_ => StubHandler.Json(new Route("""{"rc":"NOT_LICENSED"}""", 403)));
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { ApiKey = "k", Retries = 2 });
        var path = Path.Combine(TempDir(), "unlicensed.csv.gz");

        var error = await Assert.ThrowsAsync<VpnDetectionException>(
            () => client.Database.DownloadAsync("hosting_ip_v1", DatabaseFormat.Csvgz, path));

        Assert.Equal(ErrorKind.Forbidden, error.Kind);
        Assert.Equal(403, error.StatusCode);
        Assert.Equal("NOT_LICENSED", error.Message);
        Assert.False(error.Retryable);
        Assert.Single(handler.Calls);
        Assert.False(File.Exists(path + ".part"), "a refused download still created a file");
    }

    // Recognisable bytes rather than zeroes, so a copy that dropped or reordered a chunk shows up
    // as a mismatch instead of matching by accident. Two chunks and a bit, to cross the buffer.
    private static byte[] Payload()
    {
        var bytes = new byte[(64 * 1024 * 2) + 1234];
        new Random(20260904).NextBytes(bytes);
        return bytes;
    }

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "vpndetection-tests-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}

// A real HTTP origin that answers the download endpoint with a 302 to a SECOND origin, so "the
// client followed the redirect" is observable rather than assumed. Two origins, because that is
// what production does: the API redirects to object storage on another host.
//
// Storage is a raw socket rather than an HttpListener, so a response can be malformed on purpose:
// promise a gigabyte and never finish it, or declare a length and stop half way through it.
internal sealed class RedirectingServer : IDisposable
{
    private readonly HttpListener api = new();
    private readonly TcpListener storage;
    private readonly byte[]? payload;
    private readonly bool truncate;
    private readonly List<Socket> held = new();

    /// <summary>An origin whose storage stalls: a gigabyte promised, one byte sent, never closed.</summary>
    /// <remarks>
    /// Anything that READS that body blocks forever rather than merely being slow, which is what
    /// makes "the redirect was followed" fail a test instead of just costing it time.
    /// </remarks>
    internal RedirectingServer()
        : this(null, false)
    {
    }

    /// <summary>An origin whose storage serves <paramref name="payload"/>, whole or cut short.</summary>
    internal RedirectingServer(byte[]? payload, bool truncate)
    {
        this.payload = payload;
        this.truncate = truncate;
        BaseUrl = $"http://127.0.0.1:{FreePort()}";
        storage = new TcpListener(IPAddress.Loopback, 0);
        storage.Start();
        PayloadUrl = $"http://127.0.0.1:{((IPEndPoint)storage.LocalEndpoint).Port}/dataset.mmdb";
        api.Prefixes.Add($"{BaseUrl}/");
        api.Start();
        _ = Task.Run(ServeApiAsync);
        _ = Task.Run(ServeStorageAsync);
    }

    internal string BaseUrl { get; }

    internal string PayloadUrl { get; }

    internal bool StorageWasAsked => StorageRequests > 0;

    /// <summary>How many times storage was asked for the file.</summary>
    internal int StorageRequests { get; private set; }

    /// <summary>
    /// The Authorization header storage received, or null when it received none.
    /// </summary>
    /// <remarks>
    /// The header, not the key: the presigned URL authorizes itself, so the API key must never
    /// reach this host, and a test that only counted requests would not see it if it did.
    /// </remarks>
    internal string? StorageAuthorization { get; private set; }

    public void Dispose()
    {
        ((IDisposable)api).Dispose();
        storage.Stop();
        lock (held)
        {
            foreach (var socket in held)
            {
                socket.Dispose();
            }
            held.Clear();
        }
    }

    private async Task ServeApiAsync()
    {
        while (api.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await api.GetContextAsync();
            }
            catch (Exception)
            {
                return;
            }
            context.Response.StatusCode = 302;
            context.Response.RedirectLocation = PayloadUrl;
            context.Response.Close();
        }
    }

    private async Task ServeStorageAsync()
    {
        while (true)
        {
            Socket socket;
            try
            {
                socket = await storage.AcceptSocketAsync();
            }
            catch (Exception)
            {
                return;
            }
            lock (held)
            {
                held.Add(socket);
            }
            _ = Task.Run(() => AnswerAsync(socket));
        }
    }

    private async Task AnswerAsync(Socket socket)
    {
        var stream = new NetworkStream(socket, ownsSocket: false);
        var head = await ReadHeadAsync(stream);
        foreach (var line in head.Split("\r\n"))
        {
            if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
            {
                StorageAuthorization = line["Authorization:".Length..].Trim();
            }
        }
        StorageRequests++;

        if (payload is null)
        {
            // A gigabyte promised, one byte sent, and the socket held open: a reader hangs.
            await WriteAsync(stream, Header(1_000_000_000));
            await stream.WriteAsync(new byte[] { (byte)'x' });
            await stream.FlushAsync();
            return;
        }
        await WriteAsync(stream, Header(payload.Length));
        var sent = truncate ? payload.Length / 2 : payload.Length;
        await stream.WriteAsync(payload.AsMemory(0, sent));
        await stream.FlushAsync();
        if (truncate)
        {
            // A clean shutdown short of the declared length, which is the shape HttpClient has to
            // notice: an aborted socket would prove something weaker.
            socket.Shutdown(SocketShutdown.Both);
        }
        socket.Close();
    }

    private static string Header(long length)
        => "HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/octet-stream\r\n"
            + $"Content-Length: {length}\r\n"
            + "Connection: close\r\n\r\n";

    private static Task WriteAsync(Stream stream, string text)
        => stream.WriteAsync(Encoding.ASCII.GetBytes(text)).AsTask();

    private static async Task<string> ReadHeadAsync(Stream stream)
    {
        var head = new StringBuilder();
        var buffer = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            if (await stream.ReadAsync(buffer) == 0)
            {
                break;
            }
            head.Append((char)buffer[0]);
        }
        return head.ToString();
    }

    private static int FreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }
}
