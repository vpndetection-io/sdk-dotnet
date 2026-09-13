using System.Collections.Concurrent;

using Microsoft.Extensions.Caching.Memory;

namespace VPNDetection;

/// <summary>
/// A client for the VPNDetection API.
/// </summary>
/// <remarks>
/// <para>Build one and keep it: it owns a connection pool and a cache, both of which are wasted if
/// it is rebuilt per request. It is safe to use from several threads at once.</para>
/// <para>The cache is per instance, so an answer is never shared between two clients holding
/// different API keys and therefore entitled to different fields.</para>
/// </remarks>
public sealed class VpnDetectionClient : IDisposable
{
    /// <summary>The production API, used when no other base URL is configured.</summary>
    public const string DefaultBaseUrl = "https://api.vpndetection.io";

    private readonly WireClient wire;
    private readonly HttpClient? ownedHttpClient;
    private readonly MemoryCache? cache;
    private readonly TimeSpan cacheTtl;
    private readonly int concurrency;
    private readonly int retries;

    /// <summary>A client on the free tier, with every default.</summary>
    public VpnDetectionClient()
        : this(new VpnDetectionClientOptions(), null)
    {
    }

    /// <summary>A client that owns its <see cref="HttpClient"/>.</summary>
    public VpnDetectionClient(VpnDetectionClientOptions? options)
        : this(options ?? new VpnDetectionClientOptions(), null)
    {
    }

    /// <summary>
    /// A client that borrows an <see cref="HttpClient"/>, which is how this plays with
    /// <c>IHttpClientFactory</c> and typed-client registration.
    /// </summary>
    /// <remarks>
    /// The supplied client MUST NOT follow redirects, or <see cref="VPNDetection.DatabaseApi.DownloadUrlAsync"/>
    /// would fetch a dataset that routinely runs to gigabytes instead of returning its link.
    /// Register it with
    /// <c>.ConfigurePrimaryHttpMessageHandler(() =&gt; new HttpClientHandler { AllowAutoRedirect = false })</c>.
    /// A borrowed client is never disposed by this one, and its timeout and default headers are
    /// left alone.
    /// </remarks>
    public VpnDetectionClient(HttpClient httpClient, VpnDetectionClientOptions? options = null)
        : this(options ?? new VpnDetectionClientOptions(),
               httpClient ?? throw new ArgumentNullException(nameof(httpClient)))
    {
    }

    private VpnDetectionClient(VpnDetectionClientOptions o, HttpClient? supplied)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(o.Concurrency, 1, nameof(o.Concurrency));
        ArgumentOutOfRangeException.ThrowIfNegative(o.Retries, nameof(o.Retries));

        var http = supplied ?? o.HttpClient;
        if (http is null)
        {
            // Redirects OFF: unlike the JDK's client, .NET's follows them by default, and the
            // download endpoint answers 302 with the link this library exists to hand back.
            http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = o.RequestTimeout,
            };
            this.ownedHttpClient = http;
        }

        this.wire = new WireClient(http) { BaseUrl = o.BaseUrl, ApiKey = o.ApiKey };
        this.retries = o.Retries;
        this.concurrency = o.Concurrency;
        this.cacheTtl = o.CacheTtl;
        this.cache = o.CacheEnabled ? new MemoryCache(new MemoryCacheOptions { SizeLimit = o.CacheSize }) : null;
        this.Database = new DatabaseApi(this.wire, http, o.Retries);
    }

    /// <summary>The licensed dataset downloads, for keys that carry the <c>db.download</c> scope.</summary>
    public DatabaseApi Database { get; }

    /// <summary>
    /// Whether an address is private, loopback, link-local, documentation, multicast or otherwise
    /// not routable, including the IPv6 equivalents and the 6to4 and Teredo ranges.
    /// </summary>
    /// <remarks>
    /// These are the addresses <see cref="LookupAsync(string, CancellationToken)"/> answers locally.
    /// Exposed here so the check is reachable from the client you already hold;
    /// <see cref="Bogon.IsBogon"/> is the same check without one. C# cannot carry a static and an
    /// instance method of the same signature on one type, which is the whole reason
    /// <see cref="Bogon"/> exists.
    /// </remarks>
    public bool IsBogon(string ip) => Bogon.IsBogon(ip);

    /// <summary>Classify one address with the client's defaults.</summary>
    public Task<Result> LookupAsync(string ip, CancellationToken cancellationToken = default)
        => LookupAsync(ip, null, cancellationToken);

    /// <summary>
    /// Classify one address.
    /// </summary>
    /// <remarks>
    /// A bogon is answered locally and never reaches the network. Everything else is served, then
    /// cached for this instance.
    /// </remarks>
    /// <exception cref="VpnDetectionException">
    /// The lookup failed. Read <see cref="VpnDetectionException.Kind"/>.
    /// </exception>
    public async Task<Result> LookupAsync(
        string ip, LookupOptions? options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ip);
        if (Bogon.IsBogon(ip))
        {
            return Result.Bogon(ip);
        }
        if (cache is not null && cache.TryGetValue(ip, out Result? hit) && hit is not null)
        {
            return hit;
        }

        var result = await Wire.ExecuteAsync(
            options?.Retries ?? retries,
            async ct => Result.Of(await wire.LookupIpAsync(ip, ct).ConfigureAwait(false)),
            cancellationToken).ConfigureAwait(false);

        // Size 1 per entry, so MemoryCache's SizeLimit counts addresses rather than bytes and
        // CacheSize means what every other SDK's cache size means.
        cache?.Set(ip, result, new MemoryCacheEntryOptions
        {
            Size = 1,
            AbsoluteExpirationRelativeToNow = cacheTtl,
        });
        return result;
    }

    /// <summary>Classify many addresses concurrently, with the client's defaults.</summary>
    public Task<IReadOnlyDictionary<string, BatchResult>> LookupBatchAsync(
        IEnumerable<string> ips, CancellationToken cancellationToken = default)
        => LookupBatchAsync(ips, null, cancellationToken);

    /// <summary>
    /// Classify many addresses concurrently.
    /// </summary>
    /// <remarks>
    /// Keyed by address rather than positional, so duplicates in the input collapse to a single
    /// request and the caller never has to line two lists up. An address that fails carries its
    /// error as its value, so one bad entry cannot lose the rest of the answers. Iteration order is
    /// the order the addresses were first seen in the input.
    /// </remarks>
    public async Task<IReadOnlyDictionary<string, BatchResult>> LookupBatchAsync(
        IEnumerable<string> ips, BatchOptions? options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ips);
        var unique = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ip in ips)
        {
            if (ip is not null && seen.Add(ip))
            {
                unique.Add(ip);
            }
        }

        var perCall = options?.Retries is null ? null : new LookupOptions { Retries = options.Retries };
        var answers = new ConcurrentDictionary<string, BatchResult>(StringComparer.Ordinal);
        // Parallel.ForEachAsync bounds itself, so a per-call concurrency cannot be capped by the
        // client's the way a shared limiter would cap it.
        await Parallel.ForEachAsync(
            unique,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = options?.Concurrency ?? concurrency,
                CancellationToken = cancellationToken,
            },
            async (ip, ct) =>
            {
                try
                {
                    answers[ip] = BatchResult.Found(await LookupAsync(ip, perCall, ct).ConfigureAwait(false));
                }
                catch (VpnDetectionException e)
                {
                    answers[ip] = BatchResult.Failed(e);
                }
            }).ConfigureAwait(false);

        return new OrderedResults(unique, answers);
    }

    /// <summary>Releases the cache, and the <see cref="HttpClient"/> if this client created it.</summary>
    public void Dispose()
    {
        cache?.Dispose();
        ownedHttpClient?.Dispose();
    }
}
