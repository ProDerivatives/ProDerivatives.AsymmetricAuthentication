﻿using System;
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

        public const string DisplayName = "Asymmetric Authentication";

        internal const string EffectiveSchemeKey = "prod:tokenvalidation:effective:";
    }
}
