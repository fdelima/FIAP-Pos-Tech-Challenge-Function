using System;

namespace TokenValidationFunctionApp
{
    internal static class SecurityConfig
    {
        internal static string[] ValidIssuers = new string[1] { Environment.GetEnvironmentVariable("ValidIssuer") };
        internal static string[] ValidAudiences = new string[1] { Environment.GetEnvironmentVariable("ValidIssuer")};
        internal static string OpenIdConnectConfigurationUrl = $"{Environment.GetEnvironmentVariable("OpenIdConnectConfigurationUrl")}";
    }
}
