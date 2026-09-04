using Xunit;

namespace VPNDetection.Integration;

/// <summary>
/// Which plan tiers a run can observe, and the secret each one needs.
/// </summary>
/// <remarks>
/// A tier is observable only when its secret holds something NON-EMPTY. CI interpolates a secret
/// that does not exist to an empty string rather than leaving the variable unset, and a client
/// built with an empty key sends no authorization header at all, so an empty secret would quietly
/// run as a second unauthenticated rung and make every comparison against it vacuously true.
/// </remarks>
internal sealed record Rung(string Tier, string? Secret, bool Widens)
{
    /// <summary>
    /// Ascending, one rung per plan tier. <see cref="Widens"/> is what a rung promises against
    /// whichever observable rung sits below it: a paid tier serves strictly more, while a free key
    /// and no key at all are one entitlement reached two ways.
    /// </summary>
    /// <remarks>
    /// Field COUNTS are deliberately absent. Pinning "starter answers seven fields" turns a pricing
    /// change into a red SDK build; the relation between the tiers is what the client has to keep.
    /// </remarks>
    internal static readonly IReadOnlyList<Rung> All = new[]
    {
        new Rung("unauth", null, false),
        new Rung("free", "VPNDETECTION_STAGING_KEY_FREE", false),
        new Rung("starter", "VPNDETECTION_STAGING_KEY_STARTER", true),
        new Rung("scale", "VPNDETECTION_STAGING_KEY_SCALE", true),
        new Rung("max", "VPNDETECTION_STAGING_KEY_MAX", true),
    };

    internal static Rung Unauth => All[0];

    internal static Rung Max => All[^1];

    /// <summary>The tiers this run can exercise, in plan order.</summary>
    internal static IReadOnlyList<Rung> Observable
        => All.Where(rung => rung.SkipReason is null).ToArray();

    internal string Key
        => Secret is null ? string.Empty : (Environment.GetEnvironmentVariable(Secret) ?? string.Empty).Trim();

    /// <summary>Why this rung cannot be exercised, or null when it can.</summary>
    internal string? SkipReason
        => Secret is null || Key.Length > 0
            ? null
            : $"{Secret} is not set, so the {Tier} tier cannot be exercised";

    /// <summary>Skips the calling test, naming the secret, rather than failing for want of one.</summary>
    internal void SkipUnlessKeyed() => Assert.SkipWhen(SkipReason is not null, SkipReason ?? string.Empty);

    /// <summary>
    /// The ladder needs two rungs to say anything. The unauthenticated one is always there, so this
    /// only fires when no tier secret at all is configured.
    /// </summary>
    internal static void SkipUnlessLadder()
        => Assert.SkipWhen(Observable.Count < 2, "no tier secret is set, so there is no ladder to compare");
}
