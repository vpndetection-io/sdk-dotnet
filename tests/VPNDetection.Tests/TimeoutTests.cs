using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

using Xunit;

namespace VPNDetection.Tests;

// The request timeout is per ATTEMPT, and a per-call value replaces the client's in either
// direction. Every stall here is a real socket that took the request, and each failure is checked
// for having taken at least the timeout: a refused connection is a retryable network error too, and
// would otherwise pass for the timeout firing.
public class TimeoutTests
{
    private static readonly TimeSpan PerCall = TimeSpan.FromMilliseconds(250);

    // Timer slack, so a timeout that fired a few milliseconds early is not reported as no timeout.
    private static readonly TimeSpan AtLeast = TimeSpan.FromMilliseconds(200);

    [Theory]
    [InlineData("lookup")]
    [InlineData("myip")]
    [InlineData("entitlement")]
    [InlineData("batch")]
    public async Task APerCallTimeoutBelowTheClientsFiresAsARetryableNetworkError(string call)
    {
        using var origin = new StallingOrigin(StallingOrigin.Mode.NeverAnswer);
        // The client keeps the 30 second default, so a failure inside a few seconds is the
        // per-call value firing.
        using var client = new VpnDetectionClient(origin.Options());

        var started = Stopwatch.StartNew();
        var error = await FailureOf(client, call, PerCall).WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Equal(ErrorKind.Network, error.Kind);
        Assert.True(error.Retryable);
        Assert.Equal("the request timed out", error.Message);
        Assert.True(started.Elapsed >= AtLeast, $"failed after {started.ElapsedMilliseconds}ms");
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(10), $"took {started.ElapsedMilliseconds}ms");
        Assert.Equal(1, origin.Requests);
    }

    [Fact]
    public async Task APerCallTimeoutAboveTheClientsLengthensIt()
    {
        using var origin = new StallingOrigin(StallingOrigin.Mode.AnswerLate, TimeSpan.FromMilliseconds(800));
        using var client = new VpnDetectionClient(origin.Options(TimeSpan.FromMilliseconds(200)));

        var error = await Assert.ThrowsAsync<VpnDetectionException>(() => client.LookupAsync("9.9.9.9"));
        Assert.Equal("the request timed out", error.Message);

        var result = await client.LookupAsync(
            "9.9.9.9", new LookupOptions { RequestTimeout = TimeSpan.FromSeconds(10) });
        Assert.Equal("9.9.9.9", result.Ip);
    }

    [Fact]
    public async Task EachRetryGetsTheWholeTimeoutAgain()
    {
        using var origin = new StallingOrigin(StallingOrigin.Mode.NeverAnswer);
        using var client = new VpnDetectionClient(origin.Options(retries: 1));

        var started = Stopwatch.StartNew();
        await Assert.ThrowsAsync<VpnDetectionException>(
            () => client.LookupAsync("9.9.9.9", new LookupOptions { RequestTimeout = PerCall }));

        Assert.Equal(2, origin.Requests);
        Assert.True(started.Elapsed >= AtLeast * 2, $"two attempts took {started.ElapsedMilliseconds}ms");
    }

    // Cancelling releases the socket, but only a handler that HONORS the token then settles. A
    // borrowed HttpClient's own timeout is no help here either: it is the same token.
    [Fact]
    public async Task AHandlerThatIgnoresCancellationIsStillBounded()
    {
        var never = new TaskCompletionSource<HttpResponseMessage>();
        using var client = Stub.Client(
            new DeafHandler(never.Task), new VpnDetectionClientOptions { CacheEnabled = false, Retries = 0 });

        var call = client.LookupAsync("9.9.9.9", new LookupOptions { RequestTimeout = PerCall });
        var error = await Assert.ThrowsAsync<VpnDetectionException>(
            () => call.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(ErrorKind.Network, error.Kind);
        Assert.Equal("the request timed out", error.Message);
    }

    // The generated client reads every answer headers-first, and HttpClient.Timeout stops at the
    // head, so a body that stalls after it has to be bounded by this library's own deadline.
    [Fact]
    public async Task ABodyThatStallsAfterItsHeadIsBoundedToo()
    {
        using var origin = new StallingOrigin(StallingOrigin.Mode.StallAfterHead);
        using var client = new VpnDetectionClient(origin.Options(TimeSpan.FromMilliseconds(300)));

        var call = client.LookupAsync("9.9.9.9");
        var error = await Assert.ThrowsAsync<VpnDetectionException>(
            () => call.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(ErrorKind.Network, error.Kind);
        Assert.Equal("the request timed out", error.Message);
    }

    [Fact]
    public async Task ATimeoutThatCannotFireIsRefused()
    {
        using var client = Stub.Client(StubHandler.Lookups(new Dictionary<string, Route>()));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => client.LookupAsync("9.9.9.9", new LookupOptions { RequestTimeout = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new VpnDetectionClient(new VpnDetectionClientOptions { RequestTimeout = TimeSpan.Zero }));
    }

    private static async Task<VpnDetectionException> FailureOf(
        VpnDetectionClient client, string call, TimeSpan timeout)
    {
        var single = new LookupOptions { RequestTimeout = timeout };
        switch (call)
        {
            case "lookup":
                return await Assert.ThrowsAsync<VpnDetectionException>(
                    () => client.LookupAsync("9.9.9.9", single));
            case "myip":
                return await Assert.ThrowsAsync<VpnDetectionException>(() => client.MyIpAsync(single));
            case "entitlement":
                return await Assert.ThrowsAsync<VpnDetectionException>(
                    () => client.MyEntitlementAsync(single));
            default:
                var got = await client.LookupBatchAsync(
                    new[] { "9.9.9.9" }, new BatchOptions { RequestTimeout = timeout });
                Assert.False(got["9.9.9.9"].IsSuccess, "a chunk that timed out must carry the failure");
                return got["9.9.9.9"].Error!;
        }
    }
}

// Never answers and never looks at its cancellation token.
internal sealed class DeafHandler : HttpMessageHandler
{
    private readonly Task<HttpResponseMessage> response;

    internal DeafHandler(Task<HttpResponseMessage> response)
    {
        this.response = response;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken) => response;
}

// A real socket that takes a request in full and then does something unhelpful with it.
internal sealed class StallingOrigin : IDisposable
{
    private const string Body = """{"ip":"9.9.9.9","is_vpn":false}""";

    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly Mode mode;
    private readonly TimeSpan delay;
    private readonly List<Socket> held = new();
    private int requests;

    internal StallingOrigin(Mode mode, TimeSpan delay = default)
    {
        this.mode = mode;
        this.delay = delay;
        listener.Start();
        BaseUrl = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
        _ = Task.Run(ServeAsync);
    }

    internal enum Mode
    {
        NeverAnswer,
        AnswerLate,
        StallAfterHead,
    }

    internal string BaseUrl { get; }

    /// <summary>How many requests arrived in full.</summary>
    internal int Requests => Volatile.Read(ref requests);

    /// <summary>Options for a client that owns its HttpClient, so its RequestTimeout is live.</summary>
    internal VpnDetectionClientOptions Options(TimeSpan? requestTimeout = null, int retries = 0)
    {
        var options = new VpnDetectionClientOptions
        {
            BaseUrl = BaseUrl,
            CacheEnabled = false,
            Retries = retries,
        };
        if (requestTimeout is { } value)
        {
            options.RequestTimeout = value;
        }
        return options;
    }

    public void Dispose()
    {
        listener.Stop();
        lock (held)
        {
            foreach (var socket in held)
            {
                socket.Dispose();
            }
            held.Clear();
        }
    }

    private async Task ServeAsync()
    {
        while (true)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptSocketAsync();
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

    // Held open afterwards in every mode, so the only thing that ends a stalled call is the client.
    private async Task AnswerAsync(Socket socket)
    {
        try
        {
            var stream = new NetworkStream(socket, ownsSocket: false);
            await ReadRequestAsync(stream);
            Interlocked.Increment(ref requests);
            switch (mode)
            {
                case Mode.AnswerLate:
                    await Task.Delay(delay);
                    await WriteAsync(stream, Head() + Body);
                    break;
                case Mode.StallAfterHead:
                    await WriteAsync(stream, Head() + Body[..8]);
                    break;
            }
        }
        catch (Exception)
        {
            // The client hung up first, which is the expected ending for every stall.
        }
    }

    private static string Head()
        => "HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/json\r\n"
            + $"Content-Length: {Body.Length}\r\n"
            + "Connection: close\r\n\r\n";

    private static async Task WriteAsync(Stream stream, string text)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(text));
        await stream.FlushAsync();
    }

    // The head, then as much body as it declares, so a POST counts only once it has fully arrived.
    private static async Task ReadRequestAsync(Stream stream)
    {
        var head = new StringBuilder();
        var one = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            if (await stream.ReadAsync(one) == 0)
            {
                throw new EndOfStreamException();
            }
            head.Append((char)one[0]);
        }
        var length = 0;
        foreach (var line in head.ToString().Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                length = int.Parse(line["Content-Length:".Length..].Trim());
            }
        }
        await stream.ReadExactlyAsync(new byte[length]);
    }
}
