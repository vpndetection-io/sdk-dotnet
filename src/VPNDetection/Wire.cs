using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace VPNDetection;

// The seam between the generated wire layer and this one: retries, and the generated
// WireException turned into a VpnDetectionException.
internal static class Wire
{
    private static readonly TimeSpan BackoffBase = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan BackoffCap = TimeSpan.FromSeconds(8);

    /// <summary>
    /// The longest wait this library takes: <c>HttpClient.Timeout</c>'s own ceiling, which
    /// <c>RequestTimeout</c> shares, the longest <c>Retry-After</c> a retry waits out, and the
    /// longest part of an OAuth poll's sleep.
    /// </summary>
    internal static readonly TimeSpan LongestWait = TimeSpan.FromMilliseconds(int.MaxValue);

    // Retry-After is seconds as digits alone, or an HTTP date in one of RFC 9110's three forms,
    // always GMT. int.TryParse alone reads `+1` as a second, and DateTimeOffset.TryParse takes `1.5`
    // for a date and reads an ISO 8601 time in the machine's own zone.
    private const string Month = "(?<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";
    private const string Time = "(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})";
    private const string Day = "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)";

    // Sun, 06 Nov 1994 08:49:37 GMT
    private static readonly Regex ImfFixdate = new(
        $"^{Day}, (?<day>[0-9]{{2}}) {Month} (?<year>[0-9]{{4}}) {Time} GMT$", RegexOptions.CultureInvariant);

    // Sunday, 06-Nov-94 08:49:37 GMT
    private static readonly Regex Rfc850 = new(
        "^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), "
        + $"(?<day>[0-9]{{2}})-{Month}-(?<year>[0-9]{{2}}) {Time} GMT$", RegexOptions.CultureInvariant);

    // Sun Nov  6 08:49:37 1994
    private static readonly Regex Asctime = new(
        $"^{Day} {Month} (?<day>[ 0-9][0-9]) {Time} (?<year>[0-9]{{4}})$", RegexOptions.CultureInvariant);

    private static readonly string[] Months =
        { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /// <summary>
    /// Runs a generated call, retrying a transient failure up to <paramref name="retries"/> times.
    /// A server-supplied <c>Retry-After</c> wins over the backoff schedule, and is also the only
    /// thing that makes a 429 retryable at all.
    /// </summary>
    /// <param name="timeout">
    /// The bound on each ATTEMPT, or null for none of this library's own, which leaves a borrowed
    /// <see cref="HttpClient"/> to its own timeout.
    /// </param>
    internal static async Task<T> ExecuteAsync<T>(
        int retries, TimeSpan? timeout, Func<CancellationToken, Task<T>> call,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            VpnDetectionException failure;
            try
            {
                return await AttemptAsync(timeout, call, cancellationToken).ConfigureAwait(false);
            }
            catch (WireException e)
            {
                failure = Translate(e);
            }
            catch (ClassifiedException e)
            {
                failure = e.Failure;
            }
            catch (HttpRequestException e)
            {
                failure = new VpnDetectionException(ErrorKind.Network, e.Message, null, null, e);
            }
            catch (Exception e) when (e is TimeoutException
                || (e is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                // The caller's token is not the one that fired, so this is a timeout - this
                // library's own, or a borrowed HttpClient's - rather than a cancellation anybody
                // asked for.
                failure = new VpnDetectionException(ErrorKind.Network, "the request timed out", null, null, e);
            }

            if (attempt >= retries || !failure.Retryable)
            {
                throw failure;
            }
            // `Retry-After` is the server's number, and Task.Delay throws ArgumentOutOfRangeException
            // past ~49.7 days, so `Retry-After: 4294968` failed the call with that raw exception
            // rather than this library's own. One past LongestWait is waited out on the client's own
            // backoff instead; the 429 is still a throttle, and the error keeps the value the server
            // sent.
            var asked = failure.RetryAfter is { } wait && wait <= LongestWait ? wait : (TimeSpan?)null;
            await Task.Delay(asked ?? Backoff(attempt), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The bound one call runs under: its own value if it named one, else the client's.</summary>
    internal static TimeSpan? TimeoutFor(TimeSpan? perCall, TimeSpan? client)
    {
        if (perCall is { } value)
        {
            CheckTimeout(value, nameof(LookupOptions.RequestTimeout));
        }
        return perCall ?? client;
    }

    /// <summary>The rule <see cref="HttpClient.Timeout"/> applies, which this bound replaces.</summary>
    internal static void CheckTimeout(TimeSpan value, string name)
    {
        if (value != Timeout.InfiniteTimeSpan
            && (value <= TimeSpan.Zero || value > LongestWait))
        {
            throw new ArgumentOutOfRangeException(
                name, value, "a timeout must be positive, or Timeout.InfiniteTimeSpan");
        }
    }

    // One attempt against a deadline this library owns. Raced rather than left to the token alone:
    // cancelling releases the socket, but only a handler that HONORS the token then settles, and a
    // borrowed HttpClient's handlers need not.
    private static async Task<T> AttemptAsync<T>(
        TimeSpan? timeout, Func<CancellationToken, Task<T>> call, CancellationToken cancellationToken)
    {
        if (timeout is not { } limit || limit == Timeout.InfiniteTimeSpan)
        {
            return await call(cancellationToken).ConfigureAwait(false);
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(limit);
        var pending = call(deadline.Token);
        try
        {
            return await pending.WaitAsync(limit, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The attempt may still be running. Whatever it ends in is released rather than left
            // behind: a response nobody will read holds a connection, and an unread fault is
            // reported as unobserved.
            deadline.Cancel();
            _ = pending.ContinueWith(
                Release, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw;
        }
    }

    private static void Release<T>(Task<T> abandoned)
    {
        if (abandoned.IsCompletedSuccessfully)
        {
            (abandoned.Result as IDisposable)?.Dispose();
            return;
        }
        _ = abandoned.Exception;
    }

    internal static VpnDetectionException Translate(WireException e)
    {
        var retryAfter = RetryAfterOf(e.Headers);
        return new VpnDetectionException(
            KindOf(e.StatusCode, retryAfter), MessageOf(e), e.StatusCode, retryAfter, e);
    }

    /// <summary>
    /// A per-entry failure inside a successful batch: the status the single lookup would have
    /// answered, and its message, with no headers at all - so a 429 here is a spent allowance,
    /// which is the only kind the API puts in an entry.
    /// </summary>
    internal static VpnDetectionException FromEntry(int status, string message)
        => new(KindOf(status, null), message, status, null, null);

    /// <summary>
    /// What a status means, for the API and for object storage alike: both ends of a download run
    /// through here so the rule is written once.
    /// </summary>
    internal static ErrorKind KindOf(int status, TimeSpan? retryAfter) => status switch
    {
        400 => ErrorKind.BadRequest,
        401 => ErrorKind.Unauthorized,
        403 => ErrorKind.Forbidden,
        // Present means transient, absent means an allowance is spent. Nothing else in the
        // response separates the two.
        429 => retryAfter is null ? ErrorKind.QuotaExceeded : ErrorKind.RateLimited,
        // Any other 4xx is a CLIENT error. Falling through to ServerError would make it retryable,
        // so a bad dataset id would be retried twice before failing. Only 5xx and transport
        // failures are worth a retry. Classified on the RANGE, never on an enumerated list.
        _ => status < 500 ? ErrorKind.BadRequest : ErrorKind.ServerError,
    };

    // The two APIs behind this host answer with different envelopes: the lookup endpoint uses
    // `error`, the database endpoints use `rc`. Both are read here so a caller never has to know
    // which one they hit.
    private static string MessageOf(WireException e)
    {
        if (e is WireException<LookupError> lookup && !string.IsNullOrEmpty(lookup.Result?.Error))
        {
            return lookup.Result.Error;
        }
        if (e is WireException<Error> database && !string.IsNullOrEmpty(database.Result?.Rc))
        {
            return database.Result.Rc;
        }
        // An undocumented status, or a body that would not parse, still reaches here with its text.
        return FieldFromJson(e.Response) ?? $"request failed with status {e.StatusCode}";
    }

    private static string? FieldFromJson(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            foreach (var field in new[] { "error", "rc" })
            {
                if (doc.RootElement.TryGetProperty(field, out var value)
                    && value.ValueKind == JsonValueKind.String)
                {
                    return value.GetString();
                }
            }
        }
        catch (JsonException)
        {
            // A non-JSON body is not worth failing over; the generic message covers it.
        }
        return null;
    }

    // The generated client collects headers into a plain Dictionary keyed by the exact casing the
    // server sent, so this has to match case-insensitively rather than index by name.
    private static TimeSpan? RetryAfterOf(IReadOnlyDictionary<string, IEnumerable<string>>? headers)
    {
        if (headers is null)
        {
            return null;
        }
        string? value = null;
        foreach (var header in headers)
        {
            if (string.Equals(header.Key, "Retry-After", StringComparison.OrdinalIgnoreCase))
            {
                value = header.Value?.FirstOrDefault();
                break;
            }
        }
        return ParseRetryAfter(value);
    }

    /// <summary>
    /// A <c>Retry-After</c> value as a wait, or null when it is in neither of its two forms, which
    /// on a 429 reads as a spent allowance. Seconds past <see cref="int.MaxValue"/> are no wait
    /// either.
    /// </summary>
    internal static TimeSpan? ParseRetryAfter(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        value = value.Trim();
        // NumberStyles.None takes ASCII digits and nothing else: no sign, no point, no space.
        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
        {
            return TimeSpan.FromSeconds(seconds);
        }
        if (HttpDate(value) is not { } when)
        {
            return null;
        }
        var wait = when - DateTimeOffset.UtcNow;
        return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
    }

    // The instant an HTTP date names, or null when it is in none of the three forms or names no
    // real time, such as 31 November. The day of the week is read but not checked against the date.
    private static DateTimeOffset? HttpDate(string value)
    {
        int year;
        var m = ImfFixdate.Match(value);
        if (!m.Success)
        {
            m = Asctime.Match(value);
        }
        if (m.Success)
        {
            year = int.Parse(m.Groups["year"].Value, CultureInfo.InvariantCulture);
        }
        else if ((m = Rfc850.Match(value)).Success)
        {
            year = FullYear(int.Parse(m.Groups["year"].Value, CultureInfo.InvariantCulture));
        }
        else
        {
            return null;
        }
        try
        {
            return new DateTimeOffset(
                year,
                Array.IndexOf(Months, m.Groups["month"].Value) + 1,
                int.Parse(m.Groups["day"].Value.Trim(), CultureInfo.InvariantCulture),
                int.Parse(m.Groups["hour"].Value, CultureInfo.InvariantCulture),
                int.Parse(m.Groups["minute"].Value, CultureInfo.InvariantCulture),
                int.Parse(m.Groups["second"].Value, CultureInfo.InvariantCulture),
                TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    // RFC 850's two-digit year, read as RFC 9110 says: one that would land more than 50 years ahead
    // is the most recent past year ending in those digits.
    private static int FullYear(int twoDigits)
    {
        var now = DateTime.UtcNow.Year;
        var year = now - (now % 100) + twoDigits;
        return year > now + 50 ? year - 100 : year;
    }

    // The same header off a real response, where it is already parsed into its two forms. Object
    // storage answers this way, the generated client does not.
    internal static TimeSpan? RetryAfterOf(System.Net.Http.Headers.HttpResponseHeaders headers)
    {
        if (headers.RetryAfter is not { } value)
        {
            return null;
        }
        if (value.Delta is { } delta)
        {
            return delta >= TimeSpan.Zero ? delta : null;
        }
        if (value.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }
        return null;
    }

    private static TimeSpan Backoff(int attempt)
    {
        var wait = BackoffBase * Math.Pow(2, Math.Min(attempt, 16));
        return wait > BackoffCap ? BackoffCap : wait;
    }
}

// A failure an attempt has already classified, carried out of it so ExecuteAsync retries it by the
// same rule as a generated call's. A VpnDetectionException thrown inside an attempt escapes
// unretried, which OauthException relies on, so a failure that must be retried wraps itself in this.
internal sealed class ClassifiedException(VpnDetectionException failure)
    : Exception(failure.Message, failure)
{
    internal VpnDetectionException Failure { get; } = failure;
}

// The generated client emits no auth plumbing at all and knows nothing about redirects, so both
// go on through the two hooks it does leave open.
internal partial class WireClient
{
    private string? apiAuthority;

    internal string? ApiKey { get; set; }

    // NSwag gives a scalar enum property its own JsonStringEnumConverter, but where an enum sits
    // inside a LIST it writes a "TODO: Add string enum item converter" comment and nothing else,
    // and System.Text.Json's default is to read an enum as a NUMBER. So `sample_formats: ["csvgz"]`
    // throws on a perfectly healthy answer unless the converter is registered for the document.
    // Registered for the one enum that appears in a list rather than for all of them;
    // scripts/normalize_generated.py refuses to emit a client where a SECOND enum needs it.
    static partial void UpdateJsonSerializerSettings(JsonSerializerOptions settings)
        => settings.Converters.Add(new JsonStringEnumConverter<DatabaseFormat>());

    partial void PrepareRequest(HttpClient client, HttpRequestMessage request, string url)
    {
        if (!string.IsNullOrEmpty(ApiKey))
        {
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + ApiKey);
        }
    }

    // The download endpoint answers 302 and this library hands the link back rather than the
    // bytes. An HttpClient that follows redirects turns that into a multi-gigabyte read, and .NET
    // follows them by DEFAULT, so a borrowed client is the dangerous case. Catching it here stops
    // the transfer before the generated code reads the body.
    partial void ProcessResponse(HttpClient client, HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            return;
        }
        var final = response.RequestMessage?.RequestUri;
        var api = ApiAuthority();
        if (final is null || !final.IsAbsoluteUri || api.Length == 0)
        {
            return;
        }
        if (!string.Equals(final.Authority, api, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"the API redirected to {final.Authority} and the HttpClient followed it; "
                + "set AllowAutoRedirect = false on its handler so a dataset download returns a "
                + "link instead of gigabytes of data");
        }
    }

    private string ApiAuthority()
        => apiAuthority ??= Uri.TryCreate(BaseUrl, UriKind.Absolute, out var parsed)
            ? parsed.Authority
            : string.Empty;
}
