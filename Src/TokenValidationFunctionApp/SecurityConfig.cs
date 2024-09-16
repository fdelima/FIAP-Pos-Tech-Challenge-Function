using System;

namespace TokenValidationFunctionApp
{
    internal static class SecurityConfig
    {
        internal static string[] ValidIssuers = [Environment.GetEnvironmentVariable("ValidIssuer")];
        internal static string[] ValidAudiences = [Environment.GetEnvironmentVariable("ValidIssuer")];
        internal static string OpenIdConnectConfigurationUrl = $"{Environment.GetEnvironmentVariable("OpenIdConnectConfigurationUrl")}";
    }
}
