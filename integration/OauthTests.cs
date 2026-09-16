using Xunit;

namespace VPNDetection.Integration;

// The oauth accessor against staging, on a keyless client. Only calls that cannot touch anybody's
// sign-in: discovery, revoking and exchanging codes that were never issued, and ONE device
// authorization per run, because its limit of 30 a minute is per source address and shared. Nothing
// polls: nobody approves the code, and it expires on its own.
public class OauthTests
{
    private const string ClientId = "vpndetection-cli";

    [Fact]
    public async Task MetadataNamesStagingAsTheIssuer()
    {
        using var client = Keyless();

        var metadata = await client.Oauth.MetadataAsync();

        Assert.Equal(Staging.BaseUrl, metadata.Issuer);
        Assert.NotNull(metadata.DeviceAuthorizationEndpoint);
        Assert.Contains("S256", metadata.CodeChallengeMethodsSupported ?? Array.Empty<string>());
    }

    [Fact]
    public async Task RevokeAcceptsATokenThatWasNeverIssued()
    {
        using var client = Keyless();

        await client.Oauth.RevokeAsync(ClientId, "mo_rt_sdk-ci-not-a-token");
    }

    [Fact]
    public async Task ADeviceCodeThatWasNeverIssuedIsTheExpiredTokenRefusal()
    {
        using var client = Keyless();

        var error = await Assert.ThrowsAsync<OauthExpiredTokenException>(
            () => client.Oauth.ExchangeDeviceCodeAsync(ClientId, "mo_dc_sdk-ci-not-a-code"));

        Assert.Equal(400, error.StatusCode);
    }

    [Fact]
    public async Task ADeviceAuthorizationStartsASignInOrIsToldToSlowDown()
    {
        using var client = Keyless();

        try
        {
            var device = await client.Oauth.DeviceAuthorizationAsync(
                ClientId, new DeviceAuthorizationOptions { Scope = "account.read" });

            Assert.False(string.IsNullOrEmpty(device.DeviceCode), "no device_code");
            Assert.False(string.IsNullOrEmpty(device.UserCode), "no user_code");
            Assert.EndsWith("/device", device.VerificationUri);
            Assert.True(device.ExpiresIn > 0, "expires_in must be positive");
            Assert.True(device.Interval > 0, "interval must be positive");
        }
        catch (OauthException e) when (e.ErrorCode == "slow_down")
        {
            // Other runs on this address used the minute's allowance. The refusal is still the
            // accessor working.
        }
    }

    private static VpnDetectionClient Keyless()
        => new(new VpnDetectionClientOptions { BaseUrl = Staging.BaseUrl });
}
