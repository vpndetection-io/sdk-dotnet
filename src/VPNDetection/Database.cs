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
    // One chunk of a transfer, and therefore the ceiling on what a download of any size costs in
    // memory.
    private const int ChunkBytes = 64 * 1024;

    private readonly WireClient wire;
    private readonly HttpClient transfer;
    private readonly int retries;

    internal Database(WireClient wire, HttpClient transfer, int retries)
    {
        this.wire = wire;
        this.transfer = transfer;
        this.retries = retries;
    }

    /// <summary>The dataset families your organization is licensed to download.</summary>
    /// <remarks>
    /// A license covers a FAMILY while a download names one of its versions, so the ids
    /// <see cref="DownloadAsync"/> and <see cref="ChecksumsAsync"/> take come from
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

    /// <summary>
    /// Download one dataset file to <paramref name="path"/>, and answer how many bytes arrived.
    /// </summary>
    /// <remarks>
    /// <para>The bytes land in a neighboring <c>.part</c> file that is renamed on completion, so a
    /// transfer that dies half way leaves nothing that reads as a whole dataset. Nothing beyond a
    /// single chunk is ever held in memory, whatever the dataset weighs.</para>
    /// <para>A failure DURING the transfer arrives as it happened, an <see cref="IOException"/>
    /// rather than a <see cref="VpnDetectionException"/>: a reset socket and a full disk are
    /// different problems, and only one of them is ours.</para>
    /// </remarks>
    public async Task<long> DownloadAsync(
        string id, DatasetFormat format, string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentException.ThrowIfNullOrEmpty(path);

        using var response = await FetchAsync(id, format, cancellationToken).ConfigureAwait(false);
        var partial = path + ".part";
        try
        {
            long written;
            var file = new FileStream(
                partial, FileMode.Create, FileAccess.Write, FileShare.None, ChunkBytes, useAsync: true);
            await using (file.ConfigureAwait(false))
            {
                written = await CopyAsync(response, file, cancellationToken).ConfigureAwait(false);
            }
            File.Move(partial, path, overwrite: true);
            return written;
        }
        catch
        {
            // The stream is closed by the time this runs, so the half-written file can go. Best
            // effort: the failure a caller needs to see is the one that got us here.
            try
            {
                File.Delete(partial);
            }
            catch (IOException)
            {
            }
            throw;
        }
    }

    /// <summary>Download one dataset file and hand back its bytes.</summary>
    /// <remarks>
    /// <b>This holds the entire file in memory</b>, and the catalog spans five orders of magnitude:
    /// <c>cdn_ip_v1</c> is 10 KB while <c>resproxy_ip_90d_v1</c> is 1.79 GB, past which a single
    /// array is not even allocatable. Reach for this at the small end, where the bytes go straight
    /// into a parser; use <see cref="DownloadAsync"/> for anything you have not measured.
    /// </remarks>
    public async Task<byte[]> DownloadBytesAsync(
        string id, DatasetFormat format, CancellationToken cancellationToken = default)
    {
        using var response = await FetchAsync(id, format, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var _ = body.ConfigureAwait(false);

        var declared = response.Content.Headers.ContentLength;
        if (declared is not (> 0 and <= int.MaxValue))
        {
            using var buffer = new MemoryStream();
            await body.CopyToAsync(buffer, ChunkBytes, cancellationToken).ConfigureAwait(false);
            return buffer.ToArray();
        }
        // Allocated once from the declared length: a MemoryStream grows by doubling, so on a large
        // dataset the final grow alone costs twice the file. ReadExactlyAsync is also the short-read
        // guard, throwing EndOfStreamException rather than handing back a part-filled array.
        var bytes = new byte[(int)declared.Value];
        await body.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    // Follows the 302 as a SECOND request rather than by loosening the redirect guard: the
    // presigned URL authorizes itself, so forwarding the API key would hand a credential to a host
    // with no business holding it. The key rides WireClient.PrepareRequest, which this request does
    // not go through. Measured: .NET drops Authorization across a cross-host redirect too, so this
    // is belt and braces rather than the only thing standing between the key and object storage.
    private async Task<HttpResponseMessage> FetchAsync(
        string id, DatasetFormat format, CancellationToken cancellationToken)
    {
        var url = await DownloadUrlAsync(id, format, cancellationToken).ConfigureAwait(false);
        return await Wire.ExecuteAsync(retries, async ct =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            // ResponseHeadersRead is load-bearing, not an optimization. Under the default the whole
            // body is read inside SendAsync, and HttpClient.Timeout covers all of it, so a 30
            // second client would abandon any dataset that takes longer than that to move. With
            // headers-only the timeout stops at the response head. Measured both ways.
            var response = await transfer
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                return response;
            }
            // Left unread: the status is what separates a lapsed link from a refused one, and
            // nothing bounds the size of an error body.
            var status = (int)response.StatusCode;
            var retryAfter = Wire.RetryAfterOf(response.Headers);
            response.Dispose();
            throw new VpnDetectionException(
                Wire.KindOf(status, retryAfter),
                $"object storage refused the download link with status {status}",
                status,
                retryAfter);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<long> CopyAsync(
        HttpResponseMessage response, Stream destination, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var _ = body.ConfigureAwait(false);

        var buffer = new byte[ChunkBytes];
        long written = 0;
        int read;
        // A transfer that dies mid-body is HttpClient's to notice, and it does: a Content-Length
        // that outruns the socket raises HttpIOException(ResponseEnded) here rather than ending the
        // loop, so a short file cannot reach the rename below. Measured against a server that
        // promises 1000 bytes and sends 10.
        while ((read = await body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            written += read;
        }
        return written;
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
