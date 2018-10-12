using System;
namespace ProDerivatives.AsymmetricAuthentication
{
    /// <summary>
    /// Authentication Token
    /// </summary>
    public class AuthenticationToken
    {
        public string Signature { get; set; }

        public string PublicKey { get; set; }

        public long Nonce { get; set; }
    }
}
