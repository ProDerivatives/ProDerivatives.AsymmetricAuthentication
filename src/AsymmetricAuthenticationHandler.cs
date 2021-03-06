﻿using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ProDerivatives.AsymmetricAuthentication
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
            var signatureAuthenticateResult = await AuthenticateAsync(Request, Options, _logger);
            if (signatureAuthenticateResult.Succeeded)
            {
                // Signature is valid - Authenticate Bearer token

                var bearerToken = Options.BearerTokenRetriever(Request);
                if (bearerToken != null)
                {
                    // Compare subject on JWT token with signature principal and delegate to Bearer authentication if they do match
                    // in which case Bearer handler will return AuthenticateResult

                    var jwtHandler = new JwtSecurityTokenHandler();
                    var jwtReader = jwtHandler.ReadJwtToken(bearerToken);
                    if (jwtReader.Subject == signatureAuthenticateResult.Principal.Identity.Name)
                        return await Context.AuthenticateAsync("Bearer");
                    else
                        return AuthenticateResult.Fail("Bearer token subject id does not match signature public key");
                }
            }
            return signatureAuthenticateResult;
        }

        /// <summary>
        /// Tries to validate a signature on the current request
        /// </summary>
        /// <returns></returns>
        public static async Task<AuthenticateResult> AuthenticateAsync(HttpRequest request, AsymmetricAuthenticationOptions options, ILogger _logger)
        {
            _logger.LogTrace("HandleAuthenticateAsync called");

            var signatureToken = options.SignatureTokenRetriever(request);

            if (signatureToken != null)
            {

                using (var mem = new MemoryStream())
                {
                    request.EnableBuffering();
                    //request.EnableRewind();
                    await request.Body.CopyToAsync(mem);
                    request.Body.Position = 0;
                    mem.Position = 0;
                    using (var reader = new StreamReader(mem))
                    {
                        string body = string.Empty;
                        // Ignore body if file upload
                        if (request.ContentType != null && !request.ContentType.StartsWith("multipart/form-data", StringComparison.InvariantCultureIgnoreCase))
                            body = reader.ReadToEnd();

                        //remove signature token from query params if passed in header
                        var queryString = request.QueryString.Value;
                        var authenticationScheme = request.Query["scheme"];
                        if (!string.IsNullOrEmpty(authenticationScheme) && authenticationScheme == AsymmetricAuthenticationDefaults.AuthenticationScheme)
                            queryString = RemoveAuthenticationToken(request.QueryString.Value);

                        var message = $"{signatureToken.Nonce}|{request.Method.ToUpper()}|{request.Path.Value}{queryString}|{body}";
                        var isSignatureValid = options.SignatureValidator(signatureToken, message);
                        if (!isSignatureValid)
                        {
                            _logger.LogWarning($"Signature invalid. PublicKey: {signatureToken.PublicKey}, Signature: {signatureToken.Signature}, Message: {message}");
                            return AuthenticateResult.Fail("Signature invalid");
                        } 
                    }
                }

                var id = new ClaimsIdentity(AsymmetricAuthenticationDefaults.AuthenticationScheme);
                id.AddClaim(new Claim(ClaimTypes.Name, signatureToken.PublicKey));
                id.AddClaim(new Claim(JwtClaimTypes.Subject, signatureToken.PublicKey));
                id.AddClaim(new Claim(JwtClaimTypes.Name, signatureToken.PublicKey));
                id.AddClaim(new Claim(JwtClaimTypes.AuthenticationTime, signatureToken.Timestamp.ToString()));
                id.AddClaim(new Claim(JwtClaimTypes.Nonce, signatureToken.Nonce.ToString()));
                var principal = new ClaimsPrincipal(id);
                
                return AuthenticateResult.Success(new AuthenticationTicket(principal, AsymmetricAuthenticationDefaults.AuthenticationScheme));
            }
            else
            {
                return AuthenticateResult.NoResult();
            }
        }

        private static string RemoveAuthenticationToken(string queryString)
        {
            string result = queryString.Trim();
            var queryParams = queryString.Trim().Replace("?", string.Empty).Split('&');
            var tokenParams = new List<string> { "scheme", "nonce", "publickey", "signature", "timestamp" };
            foreach (var q in queryParams)
            {
                if (tokenParams.Contains(q.ToLower().Split('=')[0]))
                {
                    result = result.Replace($"&{q}", string.Empty);
                    result = result.Replace(q, string.Empty);
                }
            }
            if (result.EndsWith("?"))
                result = result.TrimEnd('?');
            return result;
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
