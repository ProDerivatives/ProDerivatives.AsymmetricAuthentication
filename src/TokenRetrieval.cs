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
        public static Func<HttpRequest, AuthenticationToken> FromAuthenticationHeader(string scheme = "Signature")
        {
            return (request) =>
            {
                string authentication = request.Headers["Authentication"].FirstOrDefault();

                if (string.IsNullOrEmpty(authentication))
                {
                    return null;
                }

                if (authentication.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase))
                {
                    var tokens = authentication.Split(',');
                    string nonce = ExtractTokenValue(tokens, "Nonce");
                    long nonceValue = 0;
                    long.TryParse(nonce, out nonceValue);

                    var result = new AuthenticationToken()
                    {
                        Signature = ExtractTokenValue(tokens, "Signature"),
                        PublicKey = ExtractTokenValue(tokens, "PublicKey"),
                        Nonce = nonceValue
                    };
                    return result;
                }

                return null;
            };
        }

        private static string ExtractTokenValue(string[] tokens, string token) {
            foreach (var t in tokens) {
                var currentToken = t.Trim();
                if (currentToken.StartsWith(token, StringComparison.OrdinalIgnoreCase))
                {
                    return currentToken.Substring(token.Length + 1).Trim();
                }
            }
            return String.Empty;
        }

    }
}
