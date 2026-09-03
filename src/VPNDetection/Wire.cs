using System.Text.Json;

namespace VPNDetection;

// The seam between the generated wire layer and this one: retries, and the generated
// WireException turned into a VpnDetectionException.
internal static class Wire
{
    private static readonly TimeSpan BackoffBase = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan BackoffCap = TimeSpan.FromSeconds(8);

    /// <summary>
    /// Runs a generated call, retrying a transient failure up to <paramref name="retries"/> times.
    /// A server-supplied <c>Retry-After</c> wins over the backoff schedule, and is also the only
    /// thing that makes a 429 retryable at all.
    /// </summary>
    internal static async Task<T> ExecuteAsync<T>(
        int retries, Func<CancellationToken, Task<T>> call, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            VpnDetectionException failure;
            try
            {
                return await call(cancellationToken).ConfigureAwait(false);
            }
            catch (WireException e)
            {
                failure = Translate(e);
            }
            catch (HttpRequestException e)
            {
                failure = new VpnDetectionException(ErrorKind.Network, e.Message, null, null, e);
            }
            catch (OperationCanceledException e) when (!cancellationToken.IsCancellationRequested)
            {
                // The caller's token is not the one that fired, so this is the HttpClient's own
                // timeout rather than a cancellation anybody asked for.
                failure = new VpnDetectionException(ErrorKind.Network, "the request timed out", null, null, e);
            }

            if (attempt >= retries || !failure.Retryable)
            {
                throw failure;
            }
            await Task.Delay(failure.RetryAfter ?? Backoff(attempt), cancellationToken).ConfigureAwait(false);
        }
    }

    internal static VpnDetectionException Translate(WireException e)
    {
        var retryAfter = RetryAfterOf(e.Headers);
        var kind = e.StatusCode switch
        {
            400 => ErrorKind.BadRequest,
            401 => ErrorKind.Unauthorized,
            403 => ErrorKind.Forbidden,
            // Present means transient, absent means an allowance is spent. Nothing else in the
            // response separates the two.
            429 => retryAfter is null ? ErrorKind.QuotaExceeded : ErrorKind.RateLimited,
            // Any other 4xx is a CLIENT error. Falling through to ServerError would make it
            // retryable, so a bad dataset id would be retried twice before failing. Only 5xx and
            // transport failures are worth a retry.
            _ => e.StatusCode < 500 ? ErrorKind.BadRequest : ErrorKind.ServerError,
        };
        return new VpnDetectionException(kind, MessageOf(e), e.StatusCode, retryAfter, e);
    }

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
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        if (int.TryParse(value.Trim(), out var seconds))
        {
            return seconds >= 0 ? TimeSpan.FromSeconds(seconds) : null;
        }
        // The header also permits an HTTP date.
        if (DateTimeOffset.TryParse(value.Trim(), out var when))
        {
            var wait = when - DateTimeOffset.UtcNow;
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

// The generated client emits no auth plumbing at all and knows nothing about redirects, so both
// go on through the two hooks it does leave open.
internal partial class WireClient
{
    private string? apiAuthority;

    internal string? ApiKey { get; set; }

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
