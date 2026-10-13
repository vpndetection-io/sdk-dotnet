using System.Globalization;
using System.Net;
using Xunit;

namespace VPNDetection.Tests;

/// <summary>
/// What a call does with an answer it cannot read, a <c>Retry-After</c> in a form RFC 9110 does
/// not have, and a key that is blank or holds a control character. Each case here went wrong on
/// 5.4.1 (measured 2026-10-13 against a local origin).
/// </summary>
public class AnswerTests
{
    // Seconds are digits alone and a date is one of RFC 9110's three forms, in GMT. 5.4.1 read `+1`
    // as a second, `1.5`, `Jan 1 2099` and an ISO 8601 time as dates, and a zone-less ISO time in
    // the machine's zone.
    [Theory]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("1_0")]
    [InlineData("0x10")]
    [InlineData("1e3")]
    [InlineData("tomorrow")]
    [InlineData("2099-01-01T00:00:00")]
    [InlineData("2099-01-01T00:00:00Z")]
    [InlineData("Jan 1 2099")]
    [InlineData("Thu, 01 Jan 2099 00:00:00 PST")]
    [InlineData("Thu, 1 Jan 2099 00:00:00 GMT")]
    [InlineData("Mon, 31 Nov 2099 00:00:00 GMT")]
    [InlineData("9223372036854775807")]
    public void ARetryAfterInNeitherFormIsNoWait(string value)
        => Assert.Null(Wire.ParseRetryAfter(value));

    [Theory]
    [InlineData("7", 7)]
    [InlineData(" 7 ", 7)]
    [InlineData("0", 0)]
    public void ARetryAfterInSecondsIsThatWait(string value, int seconds)
        => Assert.Equal(TimeSpan.FromSeconds(seconds), Wire.ParseRetryAfter(value));

    // Each of the three forms, an hour ahead and read as GMT whatever the machine's zone.
    [Theory]
    [InlineData("ddd, dd MMM yyyy HH:mm:ss 'GMT'")]
    [InlineData("dddd, dd-MMM-yy HH:mm:ss 'GMT'")]
    [InlineData("ddd MMM d HH:mm:ss yyyy")]
    public void ARetryAfterDateIsReadAsGmt(string format)
    {
        var at = DateTime.UtcNow.AddHours(1);
        var value = at.ToString(format, CultureInfo.InvariantCulture);
        if (format.StartsWith("ddd MMM d ", StringComparison.Ordinal) && at.Day < 10)
        {
            value = value.Replace($" {at.Day} ", $"  {at.Day} ", StringComparison.Ordinal);
        }

        var wait = Wire.ParseRetryAfter(value);

        Assert.NotNull(wait);
        Assert.InRange(wait!.Value, TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(61));
    }
}
