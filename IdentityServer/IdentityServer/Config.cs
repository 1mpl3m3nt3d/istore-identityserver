using System.Collections.Generic;

using IdentityServer4.Models;

using Microsoft.Extensions.Configuration;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("basket", "Basket"),
                new ApiScope("basket.bff", "Basket Bff"),
                new ApiScope("catalog", "Catalog"),
                new ApiScope("catalog.bff", "Catalog BFF"),
                new ApiScope("spa", "SPA"),
            };

        public static IEnumerable<Client> Clients(IConfiguration configuration)
        {
            return new Client[]
            {
                new Client
                {
                    ClientId = "spa_pkce",
                    ClientName = "SPA",
                    ClientSecrets = { new Secret("secret".Sha256()) },
                    ClientUri = $"{configuration["SpaUrl"]}",

                    AllowedCorsOrigins = { configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"], configuration["SpaUrl"] },
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "basket.bff", "catalog.bff", "openid", "profile", "spa" },

                    RedirectUris =
                    {
                        $"{configuration["SpaUrl"]}",
                        $"{configuration["SpaUrl"]}/login/callback",
                        $"{configuration["SpaUrl"]}/logout/callback",
                        $"{configuration["SpaUrl"]}/signin/callback",
                        $"{configuration["SpaUrl"]}/signin-callback-oidc",
                        $"{configuration["SpaUrl"]}/signin-oidc",
                        $"{configuration["SpaUrl"]}/signout/callback",
                        $"{configuration["SpaUrl"]}/signout-callback-oidc",
                        $"{configuration["SpaUrl"]}/signout-oidc",
                        $"{configuration["SpaUrl"]}/silentrenew",
                    },

                    PostLogoutRedirectUris =
                    {
                        $"{configuration["SpaUrl"]}",
                        $"{configuration["SpaUrl"]}/logout/callback",
                        $"{configuration["SpaUrl"]}/signout/callback",
                        $"{configuration["SpaUrl"]}/signout-callback-oidc",
                        $"{configuration["SpaUrl"]}/signout-oidc",
                    },

                    RequirePkce = true,
                    RequireConsent = false,
                    AllowAccessTokensViaBrowser = true,
                },
                new Client
                {
                    ClientId = "basketswaggerui",
                    ClientName = "Basket Swagger UI",
                    ClientUri = $"{configuration["BasketApi"]}",

                    AllowedCorsOrigins = { configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"], configuration["SpaUrl"] },
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = { "basket", "basket.bff", "openid", "profile", "spa" },

                    RedirectUris = { $"{configuration["BasketApi"]}/swagger/oauth2-redirect.html" },
                    PostLogoutRedirectUris = { $"{configuration["BasketApi"]}/swagger/" },

                    AllowAccessTokensViaBrowser = true,
                },
                new Client
                {
                    ClientId = "catalogswaggerui",
                    ClientName = "Catalog Swagger UI",
                    ClientUri = $"{configuration["CatalogApi"]}",

                    AllowedCorsOrigins = { configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"], configuration["SpaUrl"] },
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = { "catalog", "catalog.bff", "openid", "profile", "spa" },

                    RedirectUris = { $"{configuration["CatalogApi"]}/swagger/oauth2-redirect.html" },
                    PostLogoutRedirectUris = { $"{configuration["CatalogApi"]}/swagger/" },

                    AllowAccessTokensViaBrowser = true,
                },
            };
        }
    }
}
