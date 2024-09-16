using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;

namespace TokenValidationFunctionApp
{
    internal static class SecurityConfig
    {
        internal static string[] ValidIssuers = ["https://limatdx.b2clogin.com/4a69b13c-fd44-4eed-aebe-ba2646c68b54/v2.0/"];//["valid-issuer"];
        internal static string[] ValidAudiences = ["4341b09b-10dd-4b50-aedd-84a2bf2727f0"];//["valid-audience"];
        internal static string OpenIdConnectConfigurationUrl = "https://limatdx.b2clogin.com/limatdx.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_NEW_AND_LOGIN";//"https://<your-sign-in-provider>/v2.0/.well-known/openid-configuration";
    }

    public static class TokenValidationFunction
    {
        [FunctionName("TokenValidationFunction")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger logger)
        {
            try
            {


                logger.LogInformation("C# HTTP trigger function processed a request.");

                string name = req.Query["name"];

                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                dynamic data = JsonConvert.DeserializeObject(requestBody);
                name = name ?? data?.name;

                string responseMessage = string.IsNullOrEmpty(name)
                    ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                    : $"Hello, {name}. This HTTP triggered function executed successfully.";

                //return new OkObjectResult(responseMessage);

                #region [ "aqui" ]

                if (req.Headers.ContainsKey("Authorization"))
                {
                    var token = req.Headers["Authorization"][0].Replace("bearer ", "", StringComparison.OrdinalIgnoreCase);
                    var authenticated = ValidateToken(token, out var principal, logger);

                    if (authenticated && principal != null)
                    {
                        logger.LogInformation($"JWT token validation success.");
                        return new OkResult();
                    }
                    else
                    {
                        logger.LogInformation($"JWT token validation failed.");
                        return new UnauthorizedObjectResult(new { Message = "JWT token invalid." });
                    }
                }
                else
                {
                    logger.LogInformation($"Missing authorization token on request.");
                    return new UnauthorizedObjectResult(new { Message = "Missing authorization token on request." });
                }
                #endregion

            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message);
                return new BadRequestObjectResult(new { Message = "Ops! Ocorreu um erro inesperado!" });
            }


        }

        private static bool ValidateToken(string token, out ClaimsPrincipal? principal, ILogger logger)
        {
            principal = null;
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            try
            {
                principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
                // ValidateToken is a success if no exception is thrown.
                return true;
            }
            catch (SecurityTokenException se)
            {
                logger.LogError($"[Authentication failed] Token validation failed: {se.Message}");
                return false;
            }
            catch (Exception ex)
            {
                logger.LogError($"[Authentication failed] Unexpected error during token validation: {ex.Message}");
                return false;
            }
        }

        private static TokenValidationParameters GetValidationParameters()
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                SecurityConfig.OpenIdConnectConfigurationUrl,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());

            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = SecurityConfig.ValidIssuers,
                ValidateAudience = true,
                ValidAudiences = SecurityConfig.ValidAudiences,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                ValidateActor = false,
                IssuerSigningKeyResolver = (token, securityToken, identifier, parameters) =>
                {
                    // Retrieve the Azure AD signing keys to validate the token.
                    var config = configurationManager.GetConfigurationAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                    return config.SigningKeys;
                }
            };
        }


    }
}
