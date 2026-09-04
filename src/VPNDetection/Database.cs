namespace VPNDetection;

/// <summary>
/// The licensed dataset downloads, reached through <see cref="VpnDetectionClient.Database"/>.
/// </summary>
/// <remarks>
/// Access is granted by contract rather than self-serve, so every method here answers
/// <see cref="ErrorKind.Unauthorized"/> for a key without the <c>db.download</c> scope.
/// </remarks>
public sealed class Database
{
    private readonly WireClient wire;
    private readonly int retries;

    internal Database(WireClient wire, int retries)
    {
        this.wire = wire;
        this.retries = retries;
    }

    /// <summary>The dataset families your organization is licensed to download.</summary>
    /// <remarks>
    /// A license covers a FAMILY while a download names one of its versions, so the ids
    /// <see cref="DownloadUrlAsync"/> and <see cref="ChecksumsAsync"/> take come from
    /// <see cref="LicensedDataset.Versions"/>.
    /// </remarks>
    public Task<IReadOnlyList<LicensedDataset>> ListAsync(CancellationToken cancellationToken = default)
        => Wire.ExecuteAsync(
            retries,
            async ct => (await wire.ListDatabasesAsync(ct).ConfigureAwait(false)).Datasets,
            cancellationToken);

    /// <summary>
    /// What is inside one dataset: schema, samples, row count and sizes.
    /// </summary>
    /// <remarks>
    /// Carries <c>Updated</c> and <c>Entries</c>, so it answers whether today's build is worth
    /// fetching without downloading anything.
    /// </remarks>
    public Task<DatasetMetadata> MetadataAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(id);
        return Wire.ExecuteAsync(retries, ct => wire.DatabaseMetadataAsync(id, ct), cancellationToken);
    }

    /// <summary>
    /// The digests of one published file, to verify a download.
    /// </summary>
    /// <remarks>
    /// The whole set is returned rather than one digest: which ones a dataset publishes is the
    /// API's choice, not this library's.
    /// </remarks>
    public Task<DatasetChecksums> ChecksumsAsync(
        string id, DatasetFormat format, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(id);
        return Wire.ExecuteAsync(
            retries,
            async ct => (await wire.DatabaseChecksumAsync(id, format, ct).ConfigureAwait(false)).Checksums,
            cancellationToken);
    }

    /// <summary>Your organization's recent download attempts, newest first.</summary>
    public Task<IReadOnlyList<Download>> DownloadsAsync(
        int? limit = null, CancellationToken cancellationToken = default)
        => Wire.ExecuteAsync(
            retries,
            async ct => (await wire.ListDownloadsAsync(limit, ct).ConfigureAwait(false)).Downloads,
            cancellationToken);

    /// <summary>
    /// The time-limited URL for one dataset file.
    /// </summary>
    /// <remarks>
    /// The API answers <c>302</c> to object storage. The URL is returned rather than the bytes so
    /// the caller decides how to transfer a file that routinely runs to gigabytes; the link
    /// authorizes the START of a transfer, so one already running is not interrupted when it lapses.
    /// </remarks>
    public Task<string> DownloadUrlAsync(
        string id, DatasetFormat format, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(id);
        return Wire.ExecuteAsync(retries, async ct =>
        {
            try
            {
                await wire.DownloadDatabaseAsync(id, format, ct).ConfigureAwait(false);
            }
            catch (WireException e) when (e.StatusCode == 302)
            {
                // The generated method treats any non-2xx as a failure, so the SUCCESS case for
                // this endpoint arrives as an exception carrying the Location header.
                var location = LocationOf(e);
                if (location is null)
                {
                    throw new VpnDetectionException(
                        ErrorKind.ServerError, "the API redirected without a Location header", 302, null, e);
                }
                return location;
            }
            throw new VpnDetectionException(
                ErrorKind.ServerError, "expected a redirect to object storage", null, null, null);
        }, cancellationToken);
    }

    private static string? LocationOf(WireException e)
    {
        foreach (var header in e.Headers)
        {
            if (string.Equals(header.Key, "Location", StringComparison.OrdinalIgnoreCase))
            {
                return header.Value?.FirstOrDefault();
            }
        }
        return null;
    }
}
