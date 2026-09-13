# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="24"/>](https://vpndetection.io/) VPNDetection .NET Client Library

[![NuGet](https://img.shields.io/nuget/v/VPNDetection.svg)](https://www.nuget.org/packages/VPNDetection)
[![license](https://img.shields.io/nuget/l/VPNDetection.svg)](LICENSE)

The official .NET client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```bash
dotnet add package VPNDetection
```

Targets .NET 8 and newer.

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```csharp
using VPNDetection;

using var client = new VpnDetectionClient();

var result = await client.LookupAsync("45.83.91.1");
Console.WriteLine(result.IsVpn);   // True
```

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```csharp
using var client = new VpnDetectionClient(new VpnDetectionClientOptions
{
    ApiKey = Environment.GetEnvironmentVariable("VPNDETECTION_API_KEY"),
});

var result = await client.LookupAsync("45.83.91.1");
Console.WriteLine(result.IsVpn);            // True
Console.WriteLine(result.Vpn?.Provider);    // mullvad
Console.WriteLine(result.IsHosting);        // True
Console.WriteLine(result.Hosting?.Provider);
```

### Batch lookup

You can do batch lookups with a list, which parallelizes requests for you efficiently:

```csharp
var results = await client.LookupBatchAsync(new[] { "45.83.91.1", "8.8.8.8", "1.1.1.1" });

foreach (var (ip, answer) in results)
{
    if (!answer.IsSuccess)
    {
        Console.Error.WriteLine($"{ip}: {answer.Error!.Message}");
        continue;
    }
    Console.WriteLine($"{ip}: {answer.Result!.IsVpn}");
}
```

Results are keyed by address, so duplicates in your list collapse into a single request and one address failing never loses the rest. Iteration follows the order you passed them in.

Concurrency and other variables are configurable per-call:

```csharp
var results = await client.LookupBatchAsync(manyIps, new BatchOptions { Concurrency = 32, Retries = 4 });
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```csharp
using var client = new VpnDetectionClient();

var result = await client.LookupAsync("45.83.91.1");
Console.WriteLine(result.IsVpn);    // True, API request

var result2 = await client.LookupAsync("45.83.91.1");
Console.WriteLine(result2.IsVpn);   // True, no API request, result was cached
```

You can change the default cache variables (max size, TTL, etc) on initialization, or even disable it:

```csharp
using var client = new VpnDetectionClient(new VpnDetectionClientOptions
{
    CacheSize = 50_000,
    CacheTtl = TimeSpan.FromHours(6),
});

using var noCache = new VpnDetectionClient(new VpnDetectionClientOptions { CacheEnabled = false });
```

The cache belongs to the client instance, never to the process, because two keys can be on different plans and so entitled to different fields.

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```csharp
var result = await client.LookupAsync("192.168.1.1");
result.IsBogon;   // True, this answer was computed rather than served
result.IsVpn;     // False
```

The check is available on the client, which is handy when your inputs are addresses anyway:

```csharp
client.IsBogon("10.0.0.1");   // True
client.IsBogon("8.8.8.8");    // False
```

It is also available on its own, if you want it without a client:

```csharp
VPNDetection.Bogon.IsBogon("10.0.0.1");   // True
```

### Errors

Failures throw a `VpnDetectionException` carrying a `Kind` and a `Retryable` flag:

```csharp
try
{
    await client.LookupAsync("1.1.1.1");
}
catch (VpnDetectionException e)
{
    Console.Error.WriteLine($"{e.Kind} {e.Retryable} {e.StatusCode}");
}
```

`Kind` is one of `BadRequest`, `Unauthorized`, `Forbidden`, `RateLimited`, `QuotaExceeded`, `ServerError` or `Network`.

Note that `RateLimited` and `QuotaExceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Database downloads

If your key carries the `db.download` scope, the licensed databases are available through `client.Database`. A licence covers a database FAMILY, so the ids below come from its versions. `DownloadAsync` fetches one to a path, streaming it straight to disk so that nothing bigger than a chunk is ever held in memory; or take the bytes, or the time-limited link to run the transfer yourself:

```csharp
var databases = await client.Database.ListAsync();
var id = databases[0].Versions[0].Id;                                            // "vpn_ip_extended_v1"

var written = await client.Database.DownloadAsync(id, DatasetFormat.Mmdb, $"{id}.mmdb");
var bytes = await client.Database.DownloadBytesAsync("cdn_ip_v1", DatasetFormat.Csvgz);
var url = await client.Database.DownloadUrlAsync(id, DatasetFormat.Mmdb);
```

`DownloadBytesAsync` holds the whole file in memory, and the catalog runs from `cdn_ip_v1` at 10 KB to `resproxy_ip_90d_v1` at 1.79 GB, so use `DownloadAsync` for anything you have not measured.

### Dependency injection

The client takes an `HttpClient`, so it registers as a typed client and picks up your handler pipeline, pooling and resilience policies:

```csharp
services.AddSingleton(new VpnDetectionClientOptions { ApiKey = builder.Configuration["VpnDetection:ApiKey"] });
services.AddHttpClient<VpnDetectionClient>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
```

`AllowAutoRedirect = false` matters: the database download endpoint answers `302` with the link this library hands back, and .NET's default handler would follow it and fetch the whole database instead. A client that follows redirects is refused with a clear error rather than quietly downloading gigabytes.

### Absent is not false

Only `Ip` and `IsVpn` come back on every plan. The rest are `bool?`, where `null` means "not in your plan" rather than "checked, and no".

```csharp
result.IsHosting ?? false   // when you only want the flag
result.IsHosting is null    // not in your plan
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="96"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
