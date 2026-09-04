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
        // with its body untouched and unread.
        if (response.Content.Headers.ContentType?.MediaType != "application/json"
            || response.Content.Headers.ContentLength is null or > MaxCapturedBody)
        {
            return response;
        }
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        lock (facts)
        {
            bodies[uri.AbsolutePath] = body;
        }
        var replacement = new ByteArrayContent(body);
        foreach (var header in response.Content.Headers)
        {
            replacement.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        response.Content = replacement;
        return response;
    }
}
