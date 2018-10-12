using System;
namespace ProDerivatives.AsymmetricAuthentication
{
    /// <summary>
    /// Constants for asymmetric authentication.
    /// </summary>
    public class AsymmetricAuthenticationDefaults
    {
        /// <summary>
        /// The authentication scheme
        /// </summary>
        public const string AuthenticationScheme = "Signature";

        internal const string EffectiveSchemeKey = "prod:tokenvalidation:effective:";
    }
}
