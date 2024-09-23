using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace TokenValidationFunctionApp
{
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

            }
            catch (Exception ex)
            {
                var erro = new StringBuilder(ex.Message);
                erro.AppendLine(SecurityConfig.ValidIssuers.Length.ToString());
                erro.AppendLine(SecurityConfig.ValidIssuers[0]);
                erro.AppendLine(SecurityConfig.ValidAudiences.Length.ToString());
                erro.AppendLine(SecurityConfig.ValidAudiences[0]);
                erro.AppendLine(SecurityConfig.OpenIdConnectConfigurationUrl);

                logger.LogError(ex.Message);
                return new BadRequestObjectResult(new { Message = erro.ToString() /*"Ops! Ocorreu um erro inesperado!" */});
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
