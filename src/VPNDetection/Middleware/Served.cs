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
        PutDetail(served, "vpn", result.Vpn);
        PutDetail(served, "hosting", result.Hosting);
        PutDetail(served, "relay", result.Relay);
        PutDetail(served, "tor", result.Tor);
        PutDetail(served, "cdn", result.Cdn);
        PutDetail(served, "resproxy", result.Resproxy);
        PutDetail(served, "dcproxy", result.Dcproxy);
        PutDetail(served, "mobproxy", result.Mobproxy);
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
    // turns one into the shape a condition is written against. Their fields are flat scalars, so
    // nothing here depends on how nulls are written: a null simply matches nothing.
    private static void PutDetail(Dictionary<string, object?> served, string key, object? value)
    {
        if (value is null)
        {
            return;
        }
        served[key] = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            JsonSerializer.Serialize(value, value.GetType(), DetailOptions));
    }
}
