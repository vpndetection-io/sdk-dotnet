using System.Net;
using System.Net.Sockets;

namespace VPNDetection;

/// <summary>The bogon check, without a client to hand.</summary>
/// <remarks>
/// C# cannot carry a static and an instance method of the same signature on one type, so the
/// standalone form needs its own class. <see cref="VpnDetectionClient.IsBogon"/> is the same check
/// on the client the README teaches, since a caller usually holds one already.
/// </remarks>
public static class Bogon
{
    /// <summary>
    /// Whether an address is a bogon: private, loopback, link-local, documentation, multicast or
    /// otherwise not routable on the public internet, including the IPv6 equivalents and the 6to4
    /// and Teredo ranges that wrap them.
    /// </summary>
    /// <remarks>
    /// These can never be VPN or proxy infrastructure, so the client answers them itself and they
    /// never cost a request. Anything that is not an address at all is false: this is a
    /// classification, not a validator.
    /// </remarks>
    public static bool IsBogon(string ip)
    {
        if (string.IsNullOrEmpty(ip))
        {
            return false;
        }
        // Routing on the colon rather than on the parsed family is deliberate: it puts the
        // 4-in-6 forms (::ffff:10.0.0.1) against the v6 table, which is where the canonical
        // ranges cover them, and is what every other VPNDetection SDK does.
        if (ip.Contains(':', StringComparison.Ordinal))
        {
            if (!IPAddress.TryParse(ip, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }
            var addr6 = ToUInt128(v6);
            foreach (var range in V6)
            {
                if ((addr6 & range.Mask) == range.Net)
                {
                    return true;
                }
            }
            return false;
        }

        if (!IPAddress.TryParse(ip, out var v4) || v4.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }
        var addr4 = ToUInt32(v4);
        foreach (var range in V4)
        {
            if ((addr4 & range.Mask) == range.Net)
            {
                return true;
            }
        }
        return false;
    }

    // Parsed on first use rather than at load: a consumer that never looks up an address should
    // not pay for the table.
    private static readonly Range32[] V4 = Bogons.V4.Select(ParseV4).ToArray();
    private static readonly Range128[] V6 = Bogons.V6.Select(ParseV6).ToArray();

    private readonly record struct Range32(uint Net, uint Mask);

    private readonly record struct Range128(UInt128 Net, UInt128 Mask);

    private static Range32 ParseV4(string cidr)
    {
        var (net, bits) = SplitCidr(cidr);
        var mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
        return new Range32(ToUInt32(IPAddress.Parse(net)) & mask, mask);
    }

    private static Range128 ParseV6(string cidr)
    {
        var (net, bits) = SplitCidr(cidr);
        var mask = bits == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - bits);
        return new Range128(ToUInt128(IPAddress.Parse(net)) & mask, mask);
    }

    private static (string Net, int Bits) SplitCidr(string cidr)
    {
        var slash = cidr.IndexOf('/', StringComparison.Ordinal);
        return (cidr[..slash], int.Parse(cidr[(slash + 1)..]));
    }

    private static uint ToUInt32(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        address.TryWriteBytes(bytes, out _);
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static UInt128 ToUInt128(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        UInt128 value = 0;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }
        return value;
    }
}
