namespace VPNDetection;

/// <summary>
/// What a lookup answers.
/// </summary>
/// <remarks>
/// <para>A <c>null</c> flag is one your plan does not include. It never means "we could not check",
/// so null and <c>false</c> are genuinely different answers: null is "not in your plan",
/// <c>false</c> is "checked, and no". Write <c>result.IsHosting ?? false</c> when you only care
/// whether the address is flagged, and compare against <c>null</c> when the difference matters.</para>
/// <para>A detail object that is present but empty (<see cref="Web"/>'s empty list) means the flag
/// above it is false. A populated one always carries every one of its keys.</para>
/// </remarks>
public sealed class Result
{
    private readonly LookupResponse raw;

    private Result(LookupResponse raw, bool isBogon)
    {
        this.raw = raw;
        this.IsBogon = isBogon;
    }

    internal static Result Of(LookupResponse body) => new(body, body.IsBogon ?? false);

    /// <summary>
    /// The answer a bogon gets, in the full shape the API serves at its widest plan:
    /// <see cref="IsBogon"/> true and every other flag present and false, every detail object
    /// present and empty, and the location and AS with every field empty, as the API answers a bogon.
    /// </summary>
    /// <remarks>
    /// This is deliberately the WIDEST shape regardless of your plan, so do not infer which fields
    /// your plan includes from a bogon answer.
    /// </remarks>
    internal static Result Bogon(string ip) => new(
        new LookupResponse
        {
            Ip = ip,
            IsBogon = true,
            IsVpn = false,
            IsHosting = false,
            IsRelay = false,
            IsTor = false,
            IsCdn = false,
            IsResproxy = false,
            IsDcproxy = false,
            IsMobproxy = false,
            IsPubproxy = false,
            IsAnycast = false,
            IsCarrier = false,
            IsSatellite = false,
            IsSsh = false,
            IsSmtp = false,
            IsWeb = false,
            IsDnsResolver = false,
            IsBittorrent = false,
            IsBot = false,
            Vpn = new VpnDetail(),
            Hosting = new ClassDetail(),
            Relay = new ClassDetail(),
            Tor = new ClassDetail(),
            Cdn = new ClassDetail(),
            Resproxy = new ProxyDetail(),
            Dcproxy = new ProxyDetail(),
            Mobproxy = new ProxyDetail(),
            Pubproxy = new PubproxyDetail(),
            Carrier = new CarrierDetail(),
            Satellite = new SatelliteDetail(),
            Ssh = new SshDetail(),
            Smtp = new SmtpDetail(),
            Web = Array.Empty<WebDetail>(),
            DnsResolver = new DnsResolverDetail(),
            Bittorrent = new BitTorrentDetail(),
            Bot = new BotDetail(),
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
                Region = "",
                RegionCode = "",
                City = "",
                PostalCode = "",
                Latitude = 0,
                Longitude = 0,
                AccuracyRadius = 0,
                GeonameId = "",
                DmaCode = "",
                LastChanged = "",
            },
            Asn = new Asn { Number = 0, Name = "", Domain = "", Type = "", Prefix = "", Country = "", RpkiStatus = "" },
            Company = new Company { Name = "", Domain = "", Type = "", Country = "" },
            Hostname = "",
            Abuse = new AbuseContact
            {
                Email = "",
                Name = "",
                Phone = "",
                Address = "",
                Country = "",
                Network = "",
                Validated = false,
                UnvalidatedSince = "",
            },
        },
        true);

    /// <summary>The address that was looked up, normalized.</summary>
    public string Ip => raw.Ip;

    /// <summary>Whether the address is VPN infrastructure. Every answer includes this, with or without a key.</summary>
    public bool IsVpn => raw.IsVpn;

    /// <summary>
    /// True for reserved space (private, loopback, documentation and the like), which the client
    /// answers locally without a request. A served answer carries the API's own <c>is_bogon</c>,
    /// and this reads it.
    /// </summary>
    public bool IsBogon { get; }

    /// <summary>Whether the address belongs to a hosting or cloud provider. On a paid plan.</summary>
    public bool? IsHosting => raw.IsHosting;

    /// <summary>Whether the address is a privacy relay egress. On every answer, with or without a key.</summary>
    public bool? IsRelay => raw.IsRelay;

    /// <summary>Whether the address is a Tor node. On every answer, with or without a key.</summary>
    public bool? IsTor => raw.IsTor;

    /// <summary>Whether the address belongs to a CDN. On a paid plan.</summary>
    public bool? IsCdn => raw.IsCdn;

    /// <summary>Whether the address was seen in a residential proxy pool. On a paid plan.</summary>
    public bool? IsResproxy => raw.IsResproxy;

    /// <summary>Whether the address is one a datacenter proxy service sells or runs on, a proxy company's own ranges included. On a paid plan.</summary>
    public bool? IsDcproxy => raw.IsDcproxy;

    /// <summary>Whether the address was seen in a mobile proxy pool. On a paid plan.</summary>
    public bool? IsMobproxy => raw.IsMobproxy;

    /// <summary>
    /// Whether a public proxy, one anyone can connect through, listens on the address or sends its
    /// traffic out from it. On a paid plan.
    /// </summary>
    public bool? IsPubproxy => raw.IsPubproxy;

    /// <summary>
    /// Whether the address is announced from many places at once, as a public DNS resolver's or a
    /// CDN's edge is. On every answer, with or without a key.
    /// </summary>
    public bool? IsAnycast => raw.IsAnycast;

    /// <summary>Whether the address is a mobile carrier's, where many phones can share one address. On a paid plan.</summary>
    public bool? IsCarrier => raw.IsCarrier;

    /// <summary>Whether the address is a satellite operator's. On a paid plan.</summary>
    public bool? IsSatellite => raw.IsSatellite;

    /// <summary>Whether an SSH server answered on the address. On a paid plan.</summary>
    public bool? IsSsh => raw.IsSsh;

    /// <summary>Whether a mail server answered on the address. On a paid plan.</summary>
    public bool? IsSmtp => raw.IsSmtp;

    /// <summary>Whether a web server answered on the address, on port 80 or 443. On a paid plan.</summary>
    public bool? IsWeb => raw.IsWeb;

    /// <summary>Whether an open DNS resolver answered on the address. On a paid plan.</summary>
    public bool? IsDnsResolver => raw.IsDnsResolver;

    /// <summary>Whether a BitTorrent client was seen on the address in the last 90 days. On a paid plan.</summary>
    public bool? IsBittorrent => raw.IsBittorrent;

    /// <summary>
    /// Whether an automated client uses the address, such as a search engine's or an AI company's
    /// crawler, an uptime monitor, an internet scanner or a webhook sender. On a paid plan.
    /// </summary>
    public bool? IsBot => raw.IsBot;

    /// <summary>Detail behind <see cref="IsVpn"/>. Empty when it is false. On a paid plan.</summary>
    public VpnDetail? Vpn => raw.Vpn;

    /// <summary>Detail behind <see cref="IsHosting"/>. Empty when it is false. On a paid plan.</summary>
    public ClassDetail? Hosting => raw.Hosting;

    /// <summary>Detail behind <see cref="IsRelay"/>. Empty when it is false. On every answer, with or without a key.</summary>
    public ClassDetail? Relay => raw.Relay;

    /// <summary>Detail behind <see cref="IsTor"/>. Empty when it is false. On every answer, with or without a key.</summary>
    public ClassDetail? Tor => raw.Tor;

    /// <summary>Detail behind <see cref="IsCdn"/>. Empty when it is false. On a paid plan.</summary>
    public ClassDetail? Cdn => raw.Cdn;

    /// <summary>Detail behind <see cref="IsResproxy"/>. Empty when it is false. On a paid plan.</summary>
    public ProxyDetail? Resproxy => raw.Resproxy;

    /// <summary>Detail behind <see cref="IsDcproxy"/>. Empty when it is false. On a paid plan.</summary>
    public ProxyDetail? Dcproxy => raw.Dcproxy;

    /// <summary>Detail behind <see cref="IsMobproxy"/>. Empty when it is false. On a paid plan.</summary>
    public ProxyDetail? Mobproxy => raw.Mobproxy;

    /// <summary>Detail behind <see cref="IsPubproxy"/>. Empty when it is false. On a paid plan.</summary>
    public PubproxyDetail? Pubproxy => raw.Pubproxy;

    /// <summary>Detail behind <see cref="IsCarrier"/>. Empty when it is false. On a paid plan.</summary>
    public CarrierDetail? Carrier => raw.Carrier;

    /// <summary>Detail behind <see cref="IsSatellite"/>. Empty when it is false. On a paid plan.</summary>
    public SatelliteDetail? Satellite => raw.Satellite;

    /// <summary>Detail behind <see cref="IsSsh"/>. Empty when it is false. On a paid plan.</summary>
    public SshDetail? Ssh => raw.Ssh;

    /// <summary>Detail behind <see cref="IsSmtp"/>. Empty when it is false. On a paid plan.</summary>
    public SmtpDetail? Smtp => raw.Smtp;

    /// <summary>
    /// Detail behind <see cref="IsWeb"/>: a row per port that answered, lowest first, and empty when
    /// it is false. On a paid plan.
    /// </summary>
    public IReadOnlyList<WebDetail>? Web => raw.Web;

    /// <summary>Detail behind <see cref="IsDnsResolver"/>. Empty when it is false. On a paid plan.</summary>
    public DnsResolverDetail? DnsResolver => raw.DnsResolver;

    /// <summary>Detail behind <see cref="IsBittorrent"/>. Empty when it is false. On a paid plan.</summary>
    public BitTorrentDetail? Bittorrent => raw.Bittorrent;

    /// <summary>
    /// Detail behind <see cref="IsBot"/>: whose bot uses the address, the bots it serves, what they
    /// do and whether the operator vouches for the address. Empty when it is false. On a paid plan.
    /// </summary>
    public BotDetail? Bot => raw.Bot;

    /// <summary>
    /// When the lookup sent a user agent (<see cref="LookupOptions.UserAgent"/>,
    /// <see cref="BatchOptions.UserAgents"/>), with every field: the agent it names, what kind of
    /// client that is, and its <see cref="UserAgentVerdict.Verdict"/>. Null when none was sent, on
    /// a plan that does not serve it, and on a bogon, which is answered locally.
    /// </summary>
    public UserAgentVerdict? UserAgent => raw.UserAgent;

    /// <summary>
    /// Where the address is, on every answer, with or without a key: the country and its currency on
    /// every plan, and the region, city and coordinates on a paid one, null on a plan without them.
    /// A field your plan includes is an empty string or zero where it is not known.
    /// </summary>
    public Location? Location => raw.Location;

    /// <summary>
    /// The AS announcing the address, on every answer, with or without a key, its country and RPKI
    /// status included: <see cref="VPNDetection.Asn.Number"/> is 0 where none does. Its
    /// <see cref="VPNDetection.Asn.Type"/> is a paid plan's, and reads empty on an answer without it.
    /// </summary>
    public Asn? Asn => raw.Asn;

    /// <summary>The organization the address belongs to. On a paid plan.</summary>
    public Company? Company => raw.Company;

    /// <summary>
    /// The name the address's reverse DNS (PTR) record points to, empty when it has none. On every
    /// answer, with or without a key.
    /// </summary>
    public string? Hostname => raw.Hostname;

    /// <summary>Where to report abuse from the address. On a paid plan.</summary>
    public AbuseContact? Abuse => raw.Abuse;

    /// <summary>
    /// On answers to a key on the free plan only: <c>false</c> while its organization's trial of
    /// every field lasts, <c>true</c> once the answer has Unlimited's.
    /// </summary>
    public bool? TrialExpired => raw.TrialExpired;

    /// <summary>
    /// On answers to a key on a paid plan only: <c>false</c> while the answer has every field,
    /// <c>true</c> once its organization's overage cap is reached and the answer has Unlimited's.
    /// Lookups answered past the cap are not billed.
    /// </summary>
    public bool? CapReached => raw.CapReached;

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
