using System.Collections.Generic;
using System.Text.Json;

namespace VPNDetection.Middleware;

/// <summary>
/// A <see cref="Result"/> as the wire described it, for a condition to match against.
/// </summary>
/// <remarks>
/// Built from the Result's own properties rather than by serializing it, and that is the whole
/// point: a null member means "not in your plan" and has to come out as an ABSENT key, which a
/// serializer's null-handling setting would decide for us - differently depending on how it
/// happened to be configured.
/// </remarks>
internal static class Served
{
    private static readonly JsonSerializerOptions DetailOptions = new();

    internal static Dictionary<string, object?> Of(Result result)
    {
        var served = new Dictionary<string, object?>
        {
            ["ip"] = result.Ip,
            ["is_vpn"] = result.IsVpn,
        };
        Put(served, "is_hosting", result.IsHosting);
        Put(served, "is_relay", result.IsRelay);
        Put(served, "is_tor", result.IsTor);
        Put(served, "is_cdn", result.IsCdn);
        Put(served, "is_resproxy", result.IsResproxy);
        Put(served, "is_dcproxy", result.IsDcproxy);
        Put(served, "is_mobproxy", result.IsMobproxy);
        Put(served, "is_pubproxy", result.IsPubproxy);
        Put(served, "is_anycast", result.IsAnycast);
        Put(served, "is_carrier", result.IsCarrier);
        Put(served, "is_satellite", result.IsSatellite);
        Put(served, "is_ssh", result.IsSsh);
        Put(served, "is_smtp", result.IsSmtp);
        Put(served, "is_web", result.IsWeb);
        Put(served, "is_dns_resolver", result.IsDnsResolver);
        Put(served, "is_bittorrent", result.IsBittorrent);
        Put(served, "is_bot", result.IsBot);
        PutDetail(served, "vpn", result.Vpn);
        PutDetail(served, "hosting", result.Hosting);
        PutDetail(served, "relay", result.Relay);
        PutDetail(served, "tor", result.Tor);
        PutDetail(served, "cdn", result.Cdn);
        PutDetail(served, "resproxy", result.Resproxy);
        PutDetail(served, "dcproxy", result.Dcproxy);
        PutDetail(served, "mobproxy", result.Mobproxy);
        PutDetail(served, "pubproxy", result.Pubproxy);
        PutDetail(served, "carrier", result.Carrier);
        PutDetail(served, "satellite", result.Satellite);
        PutDetail(served, "ssh", result.Ssh);
        PutDetail(served, "smtp", result.Smtp);
        PutDetail(served, "dns_resolver", result.DnsResolver);
        PutDetail(served, "bittorrent", result.Bittorrent);
        PutDetail(served, "bot", result.Bot);
        // Only with AllowBots, which sends the request's agent: `{ user_agent: { verdict: spoofed } }`.
        PutDetail(served, "user_agent", result.UserAgent);
        if (result.Web is { } web)
        {
            // A list of rows, one per port that answered, each mapped as a detail object is.
            served["web"] = web.Select(Detail).ToList();
        }
        // Not detail objects, but mapped the same way: every field set whenever the member is present.
        PutDetail(served, "location", result.Location);
        PutDetail(served, "asn", result.Asn);
        PutDetail(served, "company", result.Company);
        PutDetail(served, "abuse", result.Abuse);
        if (result.Hostname is { } hostname)
        {
            served["hostname"] = hostname;
        }
        Put(served, "trial_expired", result.TrialExpired);
        Put(served, "cap_reached", result.CapReached);
        return served;
    }

    private static void Put(Dictionary<string, object?> served, string key, bool? value)
    {
        if (value is not null)
        {
            served[key] = value.Value;
        }
    }

    // The detail models carry their wire names on JsonPropertyName, so System.Text.Json is what
    // turns one into the shape a condition is written against. Their fields are scalars, bar
    // pubproxy's list of protocols, bittorrent's of clients and bot's agents and categories, so
    // nothing here depends on how nulls are written: a null simply matches nothing.
    private static void PutDetail(Dictionary<string, object?> served, string key, object? value)
    {
        if (value is null)
        {
            return;
        }
        served[key] = Detail(value);
    }

    private static Dictionary<string, JsonElement>? Detail(object value)
        => JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            JsonSerializer.Serialize(value, value.GetType(), DetailOptions));
}
