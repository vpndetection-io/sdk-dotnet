using System.Text.Json;

using Xunit;

namespace VPNDetection.Integration;

/// <summary>What a test is allowed to remember about a request it made.</summary>
/// <remarks>
/// Only DERIVED facts leave here. A failing assertion prints its operands and these logs are
/// public, so whether the key was carried is a boolean; the request and the key never escape.
/// </remarks>
internal sealed record Fact(string Origin, string Path, bool CarriedKey);

/// <summary>
/// Records what was asked for, and holds on to small JSON answers: the client keeps the decoded
/// result, and these tests also need what the wire carried.
/// </summary>
internal sealed class RecordingHandler : DelegatingHandler
{
    // Bodies above this are never held: a dataset transfer runs through this same handler, so
    // reading one to its end here would be the multi-gigabyte mistake the SDK exists to avoid.
    private const int MaxCapturedBody = 1 << 20;

    private readonly string key;
    private readonly List<Fact> facts = new();
    private readonly Dictionary<string, byte[]> bodies = new();

    internal RecordingHandler(string key, HttpMessageHandler inner)
        : base(inner)
    {
        this.key = key;
    }

    internal IReadOnlyList<Fact> Seen
    {
        get
        {
            lock (facts)
            {
                return facts.ToArray();
            }
        }
    }

    internal bool CarriedKey => Seen.Any(fact => fact.CarriedKey);

    /// <summary>The JSON the API answered at <paramref name="path"/>, as it came off the wire.</summary>
    internal JsonElement JsonBody(string path)
    {
        byte[]? raw;
        lock (facts)
        {
            bodies.TryGetValue(path, out raw);
        }
        Assert.True(raw is not null, $"no JSON answer was captured for {path}");
        return JsonDocument.Parse(raw!).RootElement.Clone();
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var carried = key.Length > 0
            && (uri.ToString().Contains(key, StringComparison.Ordinal)
                || request.Headers.Any(header =>
                    header.Value.Any(value => value.Contains(key, StringComparison.Ordinal))));
        lock (facts)
        {
            facts.Add(new Fact(uri.GetLeftPart(UriPartial.Authority), uri.AbsolutePath, carried));
        }

        var response = await base.SendAsync(request, cancellationToken);
        // Only a small JSON answer is held. Anything else, a dataset most of all, is handed back
        // with its body untouched and unread. MediaType drops any parameter, so
        // `application/json; charset=utf-8` is JSON too.
        if (response.Content.Headers.ContentType?.MediaType != "application/json"
            || response.Content.Headers.ContentLength > MaxCapturedBody)
        {
            return response;
        }
        // An answer sent without a Content-Length (chunked, as a paid answer is) is read up to one
        // byte past the bound: within it, it is held like any other; past it, what was read goes
        // back in front of the rest, unheld.
        var original = await response.Content.ReadAsStreamAsync(cancellationToken);
        var prefix = new MemoryStream();
        var buffer = new byte[81920];
        while (prefix.Length <= MaxCapturedBody)
        {
            var read = await original.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }
            prefix.Write(buffer, 0, read);
        }
        HttpContent replacement;
        if (prefix.Length > MaxCapturedBody)
        {
            prefix.Position = 0;
            replacement = new StreamContent(new JoinedStream(prefix, original));
        }
        else
        {
            var body = prefix.ToArray();
            lock (facts)
            {
                bodies[uri.AbsolutePath] = body;
            }
            replacement = new ByteArrayContent(body);
        }
        var served = response.Content;
        foreach (var header in served.Headers)
        {
            replacement.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        response.Content = replacement;
        if (replacement is ByteArrayContent)
        {
            served.Dispose();
        }
        return response;
    }

    // What was read ahead, then the rest of the body, as one read-only stream.
    private sealed class JoinedStream : Stream
    {
        private readonly Stream first;
        private readonly Stream rest;

        internal JoinedStream(Stream first, Stream rest)
        {
            this.first = first;
            this.rest = rest;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = first.Read(buffer, offset, count);
            return read > 0 ? read : rest.Read(buffer, offset, count);
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await first.ReadAsync(buffer, cancellationToken);
            return read > 0 ? read : await rest.ReadAsync(buffer, cancellationToken);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                first.Dispose();
                rest.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
