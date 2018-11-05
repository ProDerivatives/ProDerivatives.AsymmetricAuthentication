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
        /// <param name="scheme">The scheme (defaults to Bearer).</param>
        /// <returns></returns>
        public static Func<HttpRequest, AuthenticationToken> FromAuthenticationHeader(string scheme = AsymmetricAuthenticationDefaults.AuthenticationScheme)
        {
            return (request) =>
            {
                string authentication = request.Headers[AsymmetricAuthenticationDefaults.AuthenticationScheme].FirstOrDefault();

                if (string.IsNullOrEmpty(authentication))
                {
                    return null;
                }

                var authenticationToken = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticationToken>(authentication);

                return authenticationToken;
            };
        }

    }
}
