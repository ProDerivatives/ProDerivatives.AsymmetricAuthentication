using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ProDerivatives.AsymmetricAuthentication
{
    /// <summary>
    /// Token retrieval.
    /// </summary>
    public class TokenRetrieval
    {
        /// <summary>
        /// Reads the token from the authrorization header.
        /// </summary>
        /// <param name="scheme">The scheme (defaults to Bearer).</param>
        /// <returns></returns>
        public static Func<HttpRequest, string> FromAuthorizationHeader(string scheme = "Bearer")
        {
            return (request) =>
            {
                string authorization = request.Headers["Authorization"].FirstOrDefault();

                if (string.IsNullOrEmpty(authorization))
                {
                    return null;
                }

                if (authorization.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase))
                {
                    return authorization.Substring(scheme.Length + 1).Trim();
                }

                return null;
            };
        }

        /// <summary>
        /// Reads the authentication and authorization tokens from the authrorization header.
        /// </summary>
        /// <param name="scheme">The scheme (defaults to AsymmetricAuthentication).</param>
        /// <returns></returns>
        public static Func<HttpRequest, AuthenticationToken> FromAuthenticationHeader(string scheme = AsymmetricAuthenticationDefaults.AuthenticationScheme)
        {
            return (request) =>
            {
                string authentication = request.Headers[scheme].FirstOrDefault();

                if (string.IsNullOrEmpty(authentication))
                {
                    return null;
                }

                var authenticationToken = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticationToken>(authentication);

                return authenticationToken;
            };
        }

        /// <summary>
        /// Reads the authentication and authorization tokens from query parameters in the url.
        /// </summary>
        /// <param name="scheme">The scheme (defaults to AsymmetricAuthentication).</param>
        /// <returns></returns>
        public static Func<HttpRequest, AuthenticationToken> FromQueryParameters(string scheme = AsymmetricAuthenticationDefaults.AuthenticationScheme)
        {
            return (request) =>
            {
                var authenticationScheme = request.Query["scheme"];

                if (!string.IsNullOrEmpty(authenticationScheme) && authenticationScheme == scheme)
                {
                    return new AuthenticationToken
                    {
                        Nonce = string.IsNullOrEmpty(request.Query["nonce"]) ? 0 : Convert.ToInt64(request.Query["nonce"]),
                        PublicKey = string.IsNullOrEmpty(request.Query["publicKey"]) ? string.Empty : request.Query["publicKey"].ToString(),
                        Signature = string.IsNullOrEmpty(request.Query["signature"]) ? string.Empty : request.Query["signature"].ToString(),
                        Timestamp = string.IsNullOrEmpty(request.Query["timestamp"]) ? DateTime.UtcNow : Convert.ToDateTime(request.Query["timestamp"])
                    };
                }

                return null;
            };
        }

        /// <summary>
        /// Reads the authentication data first from the header and falls back to query params if that fails
        /// </summary>
        /// <param name="scheme"></param>
        /// <returns></returns>
        public static Func<HttpRequest, AuthenticationToken> FromAuthenticationHeaderOrQueryParameters(string scheme = AsymmetricAuthenticationDefaults.AuthenticationScheme)
        {
            return (request) =>
            {

                Func<HttpRequest, AuthenticationToken> tokenRetrievalFunction = FromAuthenticationHeader(scheme);
                var token = tokenRetrievalFunction(request);

                if (token == null)
                {
                    tokenRetrievalFunction = FromQueryParameters(scheme);
                    token = tokenRetrievalFunction(request);
                }

                return token;
            };
        }
    }
}