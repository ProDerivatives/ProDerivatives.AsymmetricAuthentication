using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Linq;

namespace ProDerivatives.AsymmetricAuthentication
{
    /// <summary>
    /// Asymmetric authentication options.
    /// </summary>
    public class AsymmetricAuthenticationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Callback to retrieve Bearer token from incoming request
        /// </summary>
        public Func<HttpRequest, string> BearerTokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();

        /// <summary>
        /// Gets or sets the signature token retriever.
        /// </summary>
        /// <value>The signature token retriever.</value>
        public Func<HttpRequest, AuthenticationToken> SignatureTokenRetriever { get; set; } = TokenRetrieval.FromAuthenticationHeader();

        /// <summary>
        /// Gets or sets the signature validator.
        /// Args: AuthenticationToken, Message
        /// </summary>
        /// <value>The signature validator.</value>
        public Func<AuthenticationToken, string, bool> SignatureValidator { get; set; }
    }
}
