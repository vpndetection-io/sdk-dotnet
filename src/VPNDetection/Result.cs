namespace VPNDetection;

/// <summary>
/// What a lookup answers.
/// </summary>
/// <remarks>
/// <para>A <c>null</c> flag is one your plan does not include. It never means "we could not check",
/// so null and <c>false</c> are genuinely different answers: null is "not in your plan",
/// <c>false</c> is "checked, and no". Write <c>result.IsHosting ?? false</c> when you only care
/// whether the address is flagged, and compare against <c>null</c> when the difference matters.</para>
/// <para>A detail object that is present but empty means the flag above it is false. A populated
/// one always carries every one of its keys.</para>
/// </remarks>
public sealed class Result
{
    private readonly LookupResponse raw;

    private Result(LookupResponse raw, bool isBogon)
    {
        this.raw = raw;
        this.IsBogon = isBogon;
    }

    internal static Result Of(LookupResponse body) => new(body, false);

    /// <summary>
    /// The answer a bogon gets, in the full shape the API serves at its widest plan: every flag
    /// present and false, every detail object present and empty, and the location and AS with
    /// every field empty, as the API answers a bogon.
    /// </summary>
    /// <remarks>
    /// This is deliberately the WIDEST shape regardless of your plan, so do not infer which fields
    /// your plan includes from a bogon answer. <see cref="IsBogon"/> is how you tell a locally
    /// computed answer from a served one.
    /// </remarks>
    internal static Result Bogon(string ip) => new(
        new LookupResponse
        {
            Ip = ip,
            IsVpn = false,
            IsHosting = false,
            IsRelay = false,
            IsTor = false,
            IsCdn = false,
            IsResproxy = false,
            IsDcproxy = false,
            IsMobproxy = false,
            IsPubproxy = false,
            Vpn = new VpnDetail(),
            Hosting = new ClassDetail(),
            Relay = new ClassDetail(),
            Tor = new ClassDetail(),
            Cdn = new ClassDetail(),
            Resproxy = new ProxyDetail(),
            Dcproxy = new ProxyDetail(),
            Mobproxy = new ProxyDetail(),
            Pubproxy = new PubproxyDetail(),
            Location = new Location
            {
                Continent = "",
                ContinentName = "",
                Country = "",
                CountryName = "",
                Timezone = "",
                CurrencyCode = "",
                CurrencyName = "",
                CurrencySymbol = "",
                FlagEmoji = "",
                FlagUnicode = "",
            },
            Asn = new Asn { Number = 0, Name = "", Domain = "", Type = "", Prefix = "" },
        },
        true);

    /// <summary>The address that was looked up, normalized.</summary>
    public string Ip => raw.Ip;

    /// <summary>Whether the address is VPN infrastructure. Every answer includes this, with or without a key.</summary>
    public bool IsVpn => raw.IsVpn;

    /// <summary>Set when this answer was computed locally rather than served.</summary>
    public bool IsBogon { get; }

    /// <summary>Whether the address belongs to a hosting or cloud provider. On every paid plan.</summary>
    public bool? IsHosting => raw.IsHosting;

    /// <summary>Whether the address is a privacy relay egress. On a free key and every paid plan.</summary>
    public bool? IsRelay => raw.IsRelay;

    /// <summary>Whether the address is a Tor node. On a free key and every paid plan.</summary>
    public bool? IsTor => raw.IsTor;

    /// <summary>Whether the address belongs to a CDN. On every paid plan.</summary>
    public bool? IsCdn => raw.IsCdn;

    /// <summary>Whether the address was seen in a residential proxy pool. On every paid plan.</summary>
    public bool? IsResproxy => raw.IsResproxy;

    /// <summary>Whether the address was seen in a datacenter proxy pool. On every paid plan.</summary>
    public bool? IsDcproxy => raw.IsDcproxy;

    /// <summary>Whether the address was seen in a mobile proxy pool. On every paid plan.</summary>
    public bool? IsMobproxy => raw.IsMobproxy;

    /// <summary>
    /// Whether a public proxy, one anyone can connect through, listens on the address or sends its
    /// traffic out from it. On every paid plan.
    /// </summary>
    public bool? IsPubproxy => raw.IsPubproxy;

    /// <summary>Detail behind <see cref="IsVpn"/>. Empty when it is false. On every paid plan.</summary>
    public VpnDetail? Vpn => raw.Vpn;

    /// <summary>Detail behind <see cref="IsHosting"/>. Empty when it is false. On every paid plan.</summary>
    public ClassDetail? Hosting => raw.Hosting;

    /// <summary>Detail behind <see cref="IsRelay"/>. Empty when it is false. On a free key and every paid plan.</summary>
    public ClassDetail? Relay => raw.Relay;

    /// <summary>Detail behind <see cref="IsTor"/>. Empty when it is false. On a free key and every paid plan.</summary>
    public ClassDetail? Tor => raw.Tor;

    /// <summary>Detail behind <see cref="IsCdn"/>. Empty when it is false. On every paid plan.</summary>
    public ClassDetail? Cdn => raw.Cdn;

    /// <summary>Detail behind <see cref="IsResproxy"/>. Empty when it is false. On every paid plan.</summary>
    public ProxyDetail? Resproxy => raw.Resproxy;

    /// <summary>Detail behind <see cref="IsDcproxy"/>. Empty when it is false. On every paid plan.</summary>
    public ProxyDetail? Dcproxy => raw.Dcproxy;

    /// <summary>Detail behind <see cref="IsMobproxy"/>. Empty when it is false. On every paid plan.</summary>
    public ProxyDetail? Mobproxy => raw.Mobproxy;

    /// <summary>Detail behind <see cref="IsPubproxy"/>. Empty when it is false. On every paid plan.</summary>
    public PubproxyDetail? Pubproxy => raw.Pubproxy;

    /// <summary>
    /// Where the address is, on a free key and every paid plan: every field set, an empty string
    /// where it is not known.
    /// </summary>
    public Location? Location => raw.Location;

    /// <summary>
    /// The AS announcing the address, on a free key and every paid plan: <see cref="VPNDetection.Asn.Number"/>
    /// is 0 where none does.
    /// </summary>
    public Asn? Asn => raw.Asn;

    /// <summary>The response exactly as it came off the wire.</summary>
    /// <remarks>
    /// The same instance is handed to every later caller that hits this address in the cache, so
    /// treat it as read only.
    /// </remarks>
    public LookupResponse Raw => raw;

    /// <inheritdoc/>
    public override string ToString()
        => $"{Ip} isVpn={IsVpn} isBogon={IsBogon}";
}
