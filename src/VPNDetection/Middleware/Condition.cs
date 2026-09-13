using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace VPNDetection.Middleware;

/// <summary>
/// Deciding whether an answer is worth blocking.
/// </summary>
/// <remarks>
/// <para>A condition is written in the shape of a served answer and keyed by the same names the
/// API uses, so what you write here reads like what you get back:</para>
/// <code>
/// new Condition { ["is_vpn"] = true }
/// new Condition { ["is_vpn"] = true, ["vpn"] = new Condition { ["provider"] = "nordvpn" } }
/// new Condition { ["resproxy"] = new Condition { ["hits"] = Bound.Gte(5) } }
/// new Condition { ["vpn"] = new Condition { ["confidence"] = new[] { "high", "medium" } } }
/// </code>
/// <para>A value may be a scalar (equality, strings without regard to case), a collection meaning
/// any-of, a <see cref="Bound"/> comparing a number, or a nested condition. A member set to
/// <c>false</c> or <c>null</c> is ignored entirely - a condition states the positive signals you
/// act on, so there is no way to write "block when this is false", which would otherwise read as
/// blocking everybody.</para>
/// </remarks>
public sealed class Condition : Dictionary<string, object?>
{
    /// <summary>An empty condition. Refused by <see cref="Validate"/>, as every empty one is.</summary>
    public Condition()
    {
    }

    /// <summary>Whether an answer satisfies any of the conditions, and should be blocked.</summary>
    public static bool Matches(IReadOnlyList<Condition> conditions, Result result)
    {
        Dictionary<string, object?> served = Served.Of(result);
        return conditions.Any(one => MatchesObject(one, served));
    }

    /// <summary>
    /// The top-level members a condition names that this answer did not carry.
    /// </summary>
    /// <remarks>
    /// <para>A field your plan does not include is absent rather than false, so a condition naming
    /// one can never match and the block would silently never fire. Gating is per top-level
    /// member, which is why only the first path segment is checked: a detail object present but
    /// empty is a real answer meaning the flag is false, not a plan gap.</para>
    /// <para>A locally answered bogon needs no special case: it is synthesized in the widest
    /// shape, so every member is present and nothing reads as missing.</para>
    /// </remarks>
    public static IReadOnlyList<string> MissingMembers(
        IReadOnlyList<Condition> conditions, Result result)
    {
        Dictionary<string, object?> served = Served.Of(result);
        var missing = new List<string>();
        foreach (Condition one in conditions)
        {
            foreach (KeyValuePair<string, object?> entry in one)
            {
                if (ConstraintCount(entry.Value) == 0 || missing.Contains(entry.Key))
                {
                    continue;
                }
                if (!served.ContainsKey(entry.Key))
                {
                    missing.Add(entry.Key);
                }
            }
        }
        return missing;
    }

    /// <summary>Refuses a condition that constrains nothing.</summary>
    /// <remarks>
    /// Ignoring <c>false</c> means <c>["is_vpn"] = false</c> and an empty condition have no terms
    /// left to satisfy, so they would match every answer and block all traffic. Nobody writes that
    /// on purpose, and failing when the middleware is built beats discovering it in production.
    /// </remarks>
    public static void Validate(IReadOnlyList<Condition>? conditions)
    {
        if (conditions is null)
        {
            return;
        }
        foreach (Condition one in conditions)
        {
            if (ConstraintCount(one) == 0)
            {
                throw new ArgumentException(
                    "vpndetection: block condition constrains nothing, which would block every "
                    + "request; a member set to false or null is ignored, so state the positive "
                    + "signals you act on");
            }
        }
    }

    /// <summary>How many leaf constraints a condition actually carries.</summary>
    public static int ConstraintCount(object? condition) => condition switch
    {
        null => 0,
        false => 0,
        Bound => 1,
        IDictionary map => map.Values.Cast<object?>().Sum(ConstraintCount),
        string => 1,
        IEnumerable list => list.Cast<object?>().Sum(ConstraintCount),
        _ => 1,
    };

    private static bool MatchesObject(IDictionary condition, object? value)
    {
        if (value is not IDictionary served)
        {
            return false;
        }
        foreach (DictionaryEntry entry in condition)
        {
            if (ConstraintCount(entry.Value) == 0)
            {
                continue;
            }
            string key = (string)entry.Key;
            object? got = served.Contains(key) ? served[key] : null;
            if (!MatchesValue(entry.Value, got))
            {
                return false;
            }
        }
        return true;
    }

    // An ABSENT member arrives here as null, which is exactly what "not in your plan" looks like.
    // Every branch below must therefore reject it, which is what makes an unserved member fail a
    // match rather than pass it.
    private static bool MatchesValue(object? want, object? got)
    {
        got = Unwrap(got);
        switch (want)
        {
            case Bound bound:
                return bound.Matches(got);
            case string text:
                // Providers are lowercase slugs on the wire and a caller should not have to know
                // that, so a string compares without case.
                return got is string other
                    && string.Equals(text, other, StringComparison.OrdinalIgnoreCase);
            case bool flag:
                return got is bool actual && flag == actual;
            case IDictionary nested:
                return MatchesObject(nested, got);
            case IEnumerable anyOf:
                return anyOf.Cast<object?>().Any(entry => MatchesValue(entry, got));
            default:
                if (want is not null && Bound.TryAsDouble(want, out double wanted))
                {
                    return got is not null && Bound.TryAsDouble(got, out double actualNumber)
                        && wanted == actualNumber;
                }
                return Equals(want, got);
        }
    }

    // The detail objects come back as JsonElement, because that is what deserializing an arbitrary
    // shape gives. Comparing against one directly would fail every time.
    private static object? Unwrap(object? value) => value is JsonElement element
        ? element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            _ => value,
        }
        : value;
}
