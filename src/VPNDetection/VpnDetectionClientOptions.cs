namespace VPNDetection;

/// <summary>Settings for a <see cref="VpnDetectionClient"/>. Every one of them has a working default.</summary>
public sealed class VpnDetectionClientOptions
{
    /// <summary>
    /// Your API key. Leave it unset to use the free tier, which answers <c>ip</c> and <c>is_vpn</c>
    /// and allows 1000 requests per day per source address.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>Where the API lives. Defaults to <see cref="VpnDetectionClient.DefaultBaseUrl"/>.</summary>
    /// <remarks>
    /// This is the only place the base URL is read. A borrowed <see cref="HttpClient"/>'s
    /// <see cref="HttpClient.BaseAddress"/> is ignored, because the request path is built here.
    /// </remarks>
    public string BaseUrl { get; set; } = VpnDetectionClient.DefaultBaseUrl;

    /// <summary>Set false to answer every lookup from the network.</summary>
    public bool CacheEnabled { get; set; } = true;

    /// <summary>Maximum number of addresses held. Default 10000.</summary>
    public long CacheSize { get; set; } = 10_000;

    /// <summary>How long an answer stays fresh. Default 1 hour.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Concurrent in-flight requests during a batch. Default 8.</summary>
    public int Concurrency { get; set; } = 8;

    /// <summary>Retry attempts for a transient failure. Default 2.</summary>
    public int Retries { get; set; } = 2;

    /// <summary>
    /// How long one request may take before it is abandoned. Default 30 seconds. Ignored when you
    /// supply your own <see cref="HttpClient"/>, which carries its own timeout.
    /// </summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Use a specific <see cref="HttpClient"/>, for a proxy, a custom handler or a test double.
    /// </summary>
    /// <remarks>
    /// It MUST NOT follow redirects, or <see cref="VPNDetection.Database.DownloadUrlAsync"/> would
    /// fetch the dataset instead of returning its link. A client supplied here is never disposed.
    /// </remarks>
    public HttpClient? HttpClient { get; set; }
}

/// <summary>
/// Per-call overrides for a single lookup. Anything left null falls back to the client's setting.
/// </summary>
public sealed class LookupOptions
{
    /// <summary>Retry attempts for a transient failure.</summary>
    public int? Retries { get; init; }
}

/// <summary>Per-call overrides for one batch. Anything left null falls back to the client's setting.</summary>
/// <remarks>
/// Deliberately NOT a subclass of <see cref="LookupOptions"/>. If it were, passing one to
/// <see cref="VpnDetectionClient.LookupAsync(string, LookupOptions?, CancellationToken)"/> would
/// compile and its <see cref="Concurrency"/> would be silently ignored; as two unrelated types the
/// compiler rejects it.
/// </remarks>
public sealed class BatchOptions
{
    /// <summary>Retry attempts for a transient failure, per address.</summary>
    public int? Retries { get; init; }

    /// <summary>Concurrent in-flight requests for THIS batch only.</summary>
    public int? Concurrency { get; init; }
}
