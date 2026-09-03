using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Xunit;

namespace VPNDetection.Tests;

/// <summary>One canned HTTP answer.</summary>
internal sealed record Route(string Body, int Status = 200, IReadOnlyDictionary<string, string>? Headers = null);

// The shared conformance corpus sdk/common generates into every SDK repo, plus the two things a
// C# suite needs to read it: a stub transport that counts what it was asked for, and a way to
// compare a typed answer against language-neutral JSON.
internal static class Corpus
{
    internal static readonly JsonElement Data = Load();

    internal static JsonElement Case(string section, string name)
    {
        foreach (var entry in Data.GetProperty(section).EnumerateArray())
        {
            if (entry.GetProperty("name").GetString() == name)
            {
                return entry;
            }
        }
        throw new InvalidOperationException($"no {section} case named {name}");
    }

    // Reads a Result member by its WIRE name, so the corpus asserts the names the API serves
    // rather than the ones this library happens to have picked.
    internal static object? Member(Result result, string wireName)
    {
        var property = typeof(Result).GetProperty(Pascal(wireName))
            ?? throw new InvalidOperationException($"Result has no member for {wireName}");
        return property.GetValue(result);
    }

    internal static string Pascal(string wireName)
        => string.Concat(wireName.Split('_').Select(p => p[..1].ToUpperInvariant() + p[1..]));

    // Renders a detail object back to its wire form. Comparing THAT to the corpus checks the
    // JsonPropertyName annotations too, which a property-by-property assertion would not.
    internal static string AsWire(object? value)
        => value is null ? "null" : JsonSerializer.Serialize(value, WireOptions);

    internal static void AssertWire(JsonElement expected, object? actual, string because)
    {
        var got = JsonDocument.Parse(AsWire(actual)).RootElement;
        Assert.True(Same(expected, got), $"{because}: got {got.GetRawText()}, want {expected.GetRawText()}");
    }

    // JsonNode.DeepEquals is .NET 9, and this library's floor is net8.0.
    private static bool Same(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind)
        {
            return false;
        }
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var aProps = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                var bProps = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                return aProps.Count == bProps.Count
                    && aProps.All(p => bProps.TryGetValue(p.Key, out var other) && Same(p.Value, other));
            case JsonValueKind.Array:
                return a.EnumerateArray().SequenceEqual(b.EnumerateArray(), new SameComparer());
            default:
                return a.GetRawText() == b.GetRawText();
        }
    }

    private sealed class SameComparer : IEqualityComparer<JsonElement>
    {
        public bool Equals(JsonElement x, JsonElement y) => Same(x, y);

        public int GetHashCode(JsonElement obj) => 0;
    }

    private static readonly JsonSerializerOptions WireOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private static JsonElement Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "testdata.json");
        return JsonDocument.Parse(File.ReadAllText(path)).RootElement.Clone();
    }
}

/// <summary>
/// A transport that answers from a table and counts what it was asked for, so "never touched the
/// network" is asserted rather than assumed.
/// </summary>
internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> respond;
    private readonly List<string> calls = new();

    internal StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        this.respond = respond;
    }

    /// <summary>Every path this handler was asked for, in arrival order.</summary>
    internal IReadOnlyList<string> Calls
    {
        get
        {
            lock (calls)
            {
                return calls.ToArray();
            }
        }
    }

    /// <summary>Answers a lookup for each address in the table, and 400 for anything else.</summary>
    internal static StubHandler Lookups(IReadOnlyDictionary<string, Route> routes)
        => new(request =>
        {
            var ip = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath.TrimStart('/'));
            return routes.TryGetValue(ip, out var route)
                ? Json(route)
                : Json(new Route("""{"error":"not a valid IP address"}""", 400));
        });

    internal static HttpResponseMessage Json(Route route)
    {
        var response = new HttpResponseMessage((HttpStatusCode)route.Status)
        {
            Content = new StringContent(route.Body, Encoding.UTF8, "application/json"),
        };
        foreach (var header in route.Headers ?? new Dictionary<string, string>())
        {
            response.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return response;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (calls)
        {
            calls.Add(request.RequestUri!.PathAndQuery);
        }
        var response = respond(request);
        response.RequestMessage ??= request;
        return Task.FromResult(response);
    }
}

internal static class Stub
{
    /// <summary>A client wired to a stub transport.</summary>
    internal static VpnDetectionClient Client(
        HttpMessageHandler handler, VpnDetectionClientOptions? options = null)
    {
        var o = options ?? new VpnDetectionClientOptions();
        o.HttpClient = new HttpClient(handler);
        return new VpnDetectionClient(o);
    }

    internal static Dictionary<string, Route> Route(string ip, string body, int status = 200,
        IReadOnlyDictionary<string, string>? headers = null)
        => new() { [ip] = new Route(body, status, headers) };

    internal static string LookupBody(string ip, bool isVpn = false)
        => $$"""{"ip":"{{ip}}","is_vpn":{{(isVpn ? "true" : "false")}}}""";
}
