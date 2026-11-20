using System.Reflection;
using System.Text.RegularExpressions;

using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// Every request names this library, <c>vpndetection-dotnet/&lt;version&gt;</c>: a lookup, a batch,
/// the entitlement, a database call, OAuth's discovery, device authorization and token exchange,
/// and object storage's transfer. Read where the caller's own handler sits, on an HttpClient the
/// caller passed in, so it is what a wrapping program sees and may put its name before.
/// </summary>
public class UserAgentTests
{
    [Fact]
    public async Task EveryRequestNamesTheLibraryAndItsVersion()
    {
        var seen = new List<(string Path, string? Agent)>();
        var handler = new StubHandler(request =>
        {
            lock (seen)
            {
                seen.Add((request.RequestUri!.AbsolutePath,
                    request.Headers.TryGetValues("User-Agent", out var agent) ? string.Join(" ", agent) : null));
            }
            if (request.RequestUri!.Host == "storage.test")
            {
                return StubHandler.Json(new Route("data", 200));
            }
            return request.RequestUri.AbsolutePath switch
            {
                "/api/v1/database/download" => StubHandler.Json(new Route(
                    "", 302, new Dictionary<string, string> { ["Location"] = "https://storage.test/blob" })),
                "/8.8.8.8" => StubHandler.Json(new Route(Stub.LookupBody("8.8.8.8"))),
                "/batch" => StubHandler.Json(new Route("""{"results":{},"errors":{}}""")),
                _ => StubHandler.Json(new Route("""{"error":"no"}""", 500)),
            };
        });
        using var client = Stub.Client(handler, new VpnDetectionClientOptions { Retries = 0 });

        await client.LookupAsync("8.8.8.8");
        await client.LookupBatchAsync(["1.1.1.1", "9.9.9.9"]);
        await Record.ExceptionAsync(() => client.MyEntitlementAsync());
        await Record.ExceptionAsync(() => client.Database.ListAsync());
        await Record.ExceptionAsync(() => client.Oauth.MetadataAsync());
        await Record.ExceptionAsync(() => client.Oauth.DeviceAuthorizationAsync("client"));
        await Record.ExceptionAsync(() => client.Oauth.ExchangeDeviceCodeAsync("client", "code"));
        await client.Database.DownloadBytesAsync("cdn_ip_v1", DatabaseFormat.Mmdb);

        var version = typeof(VpnDetectionClient).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
        Assert.Matches(new Regex(@"\A[0-9]+\.[0-9]+\.[0-9]+\z"), version);
        Assert.Equal(
            new[]
            {
                "/8.8.8.8", "/batch", "/api/v1/entitlement", "/api/v1/database/list",
                "/.well-known/oauth-authorization-server", "/oauth/device_authorization", "/oauth/token",
                "/api/v1/database/download", "/blob",
            },
            seen.Select(s => s.Path).ToArray());
        Assert.All(seen, s => Assert.Equal("vpndetection-dotnet/" + version, s.Agent));
    }
}
