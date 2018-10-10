using System;
namespace ProDerivatives.AccessControl
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
