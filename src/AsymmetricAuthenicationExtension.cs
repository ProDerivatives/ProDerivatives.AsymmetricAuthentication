using System;
using Microsoft.AspNetCore.Authentication;
using ProDerivatives.AsymmetricAuthentication;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Extensions for registering the asymmetric authentication handler
    /// </summary>
    public static class AsymmetricAuthenicationExtension
    {
        /// <summary>
        /// Registers the asymmetric authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddAsymmetricAuthentication(this AuthenticationBuilder builder)
            => builder.AddAsymmetricAuthentication(AsymmetricAuthenticationDefaults.AuthenticationScheme, AsymmetricAuthenticationDefaults.DisplayName);

        /// <summary>
        /// Registers the asymmetric authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddAsymmetricAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string displayName)
            => builder.AddAsymmetricAuthentication(authenticationScheme, displayName, configureOptions: null);

        /// <summary>
        /// Registers the asymmetric authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddAsymmetricAuthentication(this AuthenticationBuilder builder, Action<AsymmetricAuthenticationOptions> configureOptions) 
            => builder.AddAsymmetricAuthentication(AsymmetricAuthenticationDefaults.AuthenticationScheme, AsymmetricAuthenticationDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Registers the asymmetric authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddAsymmetricAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<AsymmetricAuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<AsymmetricAuthenticationOptions, AsymmetricAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
