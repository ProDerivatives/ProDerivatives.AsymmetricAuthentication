# ProDerivatives.AsymmetricAuthentication
Authentication handler for .NET Standard 2.0 that allows validation of asymmetrically signed messages.

## Usage
Enable asymmetric authentication in ConfigureService method

```csharp
services.AddAuthentication(AsymmetricAuthenticationDefaults.AuthenticationScheme)
    .AddAsymmetricAuthentication(options =>
    {
        options.SignatureTokenRetriever = TokenRetrieval.FromAuthenticationHeader();
        options.SignatureValidator = VerifySignature();
    });
```

Verify signature, in this case Ethereum signatures using ProDerivatives.Ethereum nuget package

```csharp
private static Func<AuthenticationToken, string, bool> VerifySignature()
{
    return (token, message) =>
    {
        var verifyFunction = ProDerivatives.Ethereum.Signer.VerifySignature();
        return verifyFunction(token.Signature, token.PublicKey, message);
    };
}
```

### Add bearer token validation with IdentityServer
Simply specify authority and API name (aka audience):

```csharp
services.AddAuthentication(AsymmetricAuthenticationDefaults.AuthenticationScheme)
    .AddAsymmetricAuthentication(options =>
    {
        options.SignatureTokenRetriever = TokenRetrieval.FromAuthenticationHeader();
        options.SignatureValidator = VerifySignature();
    })
    .AddIdentityServerAuthentication(options =>
    {
        options.Authority = Configuration["Settings:Authority"];

        if (Configuration["ASPNETCORE_ENVIRONMENT"] == "Development")
            options.RequireHttpsMetadata = false;

        options.ApiName = "ProDerivatives";
    });
```

If bearer tokens are used then subject must match public key of signature.