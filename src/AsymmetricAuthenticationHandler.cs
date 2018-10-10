using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ProDerivatives.AccessControl
{
    /// <summary>
    /// Authentication handler for validating signed messages
    /// </summary>
    public class AsymmetricAuthenticationHandler : AuthenticationHandler<AsymmetricAuthenticationOptions>
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Tries to validate a signature on the current request
        /// </summary>
        /// <returns></returns>
        public AsymmetricAuthenticationHandler(
            IOptionsMonitor<AsymmetricAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) 
            : base(options, logger, encoder, clock)
        {
            _logger = logger.CreateLogger<AsymmetricAuthenticationHandler>();
        }

        /// <summary>
        /// Tries to validate a signature on the current request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            _logger.LogTrace("HandleAuthenticateAsync called");

            var signatureToken = Options.SignatureTokenRetriever(Context.Request);

            if (signatureToken != null)
            {
                // TODO: Check Signature and Fail signature is not valid

                var bearerToken = Options.BearerTokenRetriever(Context.Request);
                if (bearerToken != null)
                {
                    // Compare subject on JWT token with signature principal and delegate to Bearer authentication if they do match

                    var jwtHandler = new JwtSecurityTokenHandler();
                    var jwtReader = jwtHandler.ReadJwtToken(bearerToken);
                    if (jwtReader.Subject == signatureToken.PublicKey)
                        return await Context.AuthenticateAsync("Bearer");
                    else
                        return AuthenticateResult.Fail("Bearer token subject id does not match signature public key");
                }

                // Default if no bearer token present: Create claims identity from public key and authorize access
                var id = new ClaimsIdentity(AsymmetricAuthenticationDefaults.AuthenticationScheme);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, signatureToken.PublicKey));
                id.AddClaim(new Claim(JwtClaimTypes.Name, signatureToken.PublicKey));
                var principal = new ClaimsPrincipal(id);

                return AuthenticateResult.Success(new AuthenticationTicket(principal, AsymmetricAuthenticationDefaults.AuthenticationScheme));

            } else {
                return AuthenticateResult.NoResult();
            }
        }

        /// <summary>
        /// Handles the challenge async.
        /// </summary>
        /// <returns>The challenge async.</returns>
        /// <param name="properties">Properties.</param>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (Context.Items.TryGetValue(AsymmetricAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, out object value))
            {
                if (value is string scheme)
                {
                    _logger.LogTrace("Forwarding challenge to scheme: {scheme}", scheme);
                    await Context.ChallengeAsync(scheme);
                }
            }
            else
            {
                await base.HandleChallengeAsync(properties);
            }
        }
    }
}
