using System.Security.Cryptography;

using Xunit;

namespace VPNDetection.Integration;

// The licensed-download half, which only the max key can reach: it is the tier holding dataset
// licences, and db.download is a scope the other three keys do not carry.
//
// The transfer is budgeted before it starts. Metadata publishes a size per format, and that size is
// checked against the ceiling below FIRST, so a mistaken dataset id can never quietly pull one of
// the gigabyte datasets through CI.
public class DatabaseTests
{
    // The max organization licenses cdn_ip for license_type, and at ~10 KB it is the only dataset
    // small enough to move in CI.
    private const string DatasetId = "cdn_ip_v1";

    private const DatasetFormat Format = DatasetFormat.Csvgz;

    // 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so tripping it means
    // the suite is pointed somewhere unintended, which is exactly when a transfer must not proceed.
    private const long Ceiling = 8 << 20;

    /// <summary>A real catalogue id the max organization holds no licence for.</summary>
    private const string UnlicensedId = "hosting_ip_v1";

    private static readonly SemaphoreSlim TransferLock = new(1, 1);
    private static Transfer? shared;

    [Fact]
    public async Task TheLicensedCatalogueAnswersTheSchemaTheClientWasGeneratedFrom()
    {
        var (client, recorder) = MaxClient();
        using (client)
        {
            var datasets = await client.Database.ListAsync();

            Assert.NotEmpty(datasets);
            // Named first, and with what actually arrived, because every typed assertion below reads
            // as a zero value when the payload disagrees, and a bare "want a string" costs a whole
            // CI cycle to interpret.
            var served = recorder.JsonBody("/api/v1/database/list")
                .GetProperty("datasets")
                .EnumerateArray()
                .SelectMany(dataset => dataset.EnumerateObject().Select(field => field.Name))
                .Distinct()
                .Order()
                .ToArray();
            foreach (var want in new[] { "base", "versions" })
            {
                Assert.True(
                    served.Contains(want),
                    $"the payload carries {string.Join(", ", served)}, and LicensedDataset declares {want}");
            }
            // A docs-site slug, and never API surface. It was published here once.
            Assert.DoesNotContain("docsGroup", served, StringComparer.Ordinal);

            var ids = new List<string>();
            foreach (var family in datasets)
            {
                Assert.False(string.IsNullOrEmpty(family.Base), "a licensed family carries no base");
                Assert.False(string.IsNullOrEmpty(family.Name), $"{family.Base} carries no name");
                Assert.True(
                    Enum.IsDefined(family.Standing), $"{family.Base} carries an undocumented standing");
                Assert.True(
                    Enum.IsDefined(family.LicenseType), $"{family.Base} carries an undocumented right");
                // The point of the family shape: a license covers the family, and these are the ids
                // the download and checksum calls take. Before the spec was corrected this list did
                // not exist, so ListAsync could not tell a caller what to download.
                Assert.True(family.Versions.Count > 0, $"{family.Base} carries no versions");
                foreach (var version in family.Versions)
                {
                    Assert.False(string.IsNullOrEmpty(version.Id), $"{family.Base} has a version with no id");
                    Assert.True(version.Formats.Count > 0, $"{version.Id} carries no formats");
                    ids.Add(version.Id);
                }
            }
            Console.WriteLine($"licensed: {string.Join(", ", ids)}");
        }
    }

    [Fact]
    public async Task ADatasetTheOrganizationDoesNotLicenseIsRefusedCleanly()
    {
        var (client, recorder) = MaxClient();
        using (client)
        {
            var error = await Assert.ThrowsAsync<VpnDetectionException>(
                () => client.Database.DownloadUrlAsync(UnlicensedId, Format));

            Assert.Equal(ErrorKind.Forbidden, error.Kind);
            Assert.Equal(403, error.StatusCode);
            Assert.False(error.Retryable, "a licence refusal is not worth retrying");
            // The API says WHICH refusal this is (`{"rc":"NOT_LICENSED"}`). Falling back to the
            // status means the client never read the envelope.
            Assert.False(
                error.Message.StartsWith("request failed with status", StringComparison.Ordinal),
                $"Message = {error.Message}, which is the client fallback, so the body went unread");
            Assert.Single(recorder.Seen);
        }
    }

    [Fact]
    public async Task DownloadStreamsARealDatasetToDiskIntact()
    {
        var transfer = await Transferred();

        Assert.True(transfer.Written > 0, "nothing was transferred");
        Assert.Equal(transfer.Written, new FileInfo(transfer.Path).Length);
        Assert.False(File.Exists(transfer.Path + ".part"), "the .part file outlived a successful transfer");
        var body = await File.ReadAllBytesAsync(transfer.Path);
        Assert.True(body.Length > 2 && body[0] == 0x1f && body[1] == 0x8b, "the payload is not gzip");

        Assert.True(
            transfer.Checksums.Sha256?.Length == 64,
            $"sha256 = {transfer.Checksums.Sha256}, so the checksums did not unwrap past the envelope");
        Assert.Equal(transfer.Checksums.Sha256, Digest(body));

        // The presigned URL authorizes itself, so the request that follows the 302 must carry no
        // credential.
        var storage = transfer.Facts.Where(fact => fact.Origin != Staging.BaseUrl).ToArray();
        Assert.True(storage.Length > 0, "nothing was fetched from object storage, so no 302 was followed");
        foreach (var fact in storage)
        {
            Assert.False(fact.CarriedKey, $"the API key was sent to object storage at {fact.Origin}");
        }
    }

    [Fact]
    public async Task DownloadBytesAgreesWithTheStreamedCopy()
    {
        var transfer = await Transferred();
        var (client, _) = MaxClient();
        using (client)
        {
            var raw = await client.Database.DownloadBytesAsync(DatasetId, Format);

            Assert.Equal(transfer.Written, raw.LongLength);
            Assert.Equal(transfer.Checksums.Sha256, Digest(raw));
        }
    }

    // A client of its own per test, so one test's request record cannot be read through another's.
    private static (VpnDetectionClient Client, RecordingHandler Recorder) MaxClient()
    {
        Rung.Max.SkipUnlessKeyed();
        return Staging.ClientFor(Rung.Max);
    }

    // Memoized so the two transfer tests share one download rather than pulling the dataset twice
    // each. Held in a directory of the class's own, because it outlives whichever test asked first.
    private static async Task<Transfer> Transferred()
    {
        await TransferLock.WaitAsync();
        try
        {
            if (shared is not null)
            {
                return shared;
            }
            var (client, recorder) = MaxClient();
            using (client)
            {
                var metadata = await client.Database.MetadataAsync(DatasetId);
                Assert.Equal(DatasetId, metadata.Id);
                var size = PublishedSize(metadata);
                Assert.True(
                    size > 0 && size <= Ceiling,
                    $"{DatasetId} is {size} bytes, past the {Ceiling} ceiling, so it is not transferred");

                var dir = Directory.CreateTempSubdirectory("vpndetection-integration-").FullName;
                var path = Path.Combine(dir, DatasetId + ".csv.gz");
                var written = await client.Database.DownloadAsync(DatasetId, Format, path);
                // Read after the transfer, so a rebuild between the two calls shows up as a digest
                // mismatch rather than passing against a digest of nothing.
                var checksums = await client.Database.ChecksumsAsync(DatasetId, Format);
                Console.WriteLine($"{DatasetId}.{Format}: {written} bytes, metadata says {size}");

                shared = new Transfer(written, path, checksums, recorder.Seen);
                return shared;
            }
        }
        finally
        {
            TransferLock.Release();
        }
    }

    private static long PublishedSize(DatasetMetadata metadata)
    {
        Assert.True(metadata.Size is not null, $"{DatasetId} publishes no size to check a transfer against");
        Assert.True(
            metadata.Size!.TryGetValue(Format.ToString().ToLowerInvariant(), out var size),
            $"{DatasetId} publishes no {Format} size to check a transfer against");
        return size;
    }

    private static string Digest(byte[] body)
        => Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    private sealed record Transfer(
        long Written, string Path, DatasetChecksums Checksums, IReadOnlyList<Fact> Facts);
}
