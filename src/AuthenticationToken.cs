using System;
namespace ProDerivatives.AsymmetricAuthentication
{
    /// <summary>
    /// Authentication Token
    /// </summary>
    public class AuthenticationToken
    {
        /// <summary>
        /// Signature
        /// </summary>
        public string Signature { get; set; }

        /// <summary>
        /// Public Key
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// Nonce
        /// </summary>
        public long Nonce { get; set; }

        /// <summary>
        /// Timestamp
        /// </summary>
        public DateTime Timestamp { get; set; }
    }
}
