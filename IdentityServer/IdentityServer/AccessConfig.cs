using Duende.IdentityServer.Models;

namespace IdentityServer;

public static class AccessConfig
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
                new ApiScope("spa", "SPA"),
                new ApiScope("catalog", "Catalog"),
                new ApiScope("catalog.bff", "Catalog BFF"),
                new ApiScope("basket", "Basket"),
                new ApiScope("basket.bff", "Basket Bff"),
        };

    public static IEnumerable<Client> Clients(IConfiguration configuration)
    {
        return new Client[]
        {
            new Client
            {
                ClientId = "spa_pkce",
                ClientName = "SPA PKCE Client",

                ClientUri = $"{configuration["SpaUrl"]}",

                AllowedGrantTypes = GrantTypes.Code,

                ClientSecrets = { new Secret("secret".Sha256()) },

                RedirectUris =
                {
                    $"{configuration["SpaUrl"]}/signin-oidc",
                    $"{configuration["SpaUrl"]}/silentrenew",
                    $"{configuration["SpaUrl"]}/signout-oidc",
                    $"{configuration["SpaUrl"]}/logout/callback",
                    $"{configuration["GlobalUrl"]}/signin-oidc",
                    $"{configuration["GlobalUrl"]}/silentrenew",
                    $"{configuration["GlobalUrl"]}/signout-oidc",
                    $"{configuration["GlobalUrl"]}/logout/callback",
                },

                PostLogoutRedirectUris =
                {
                    $"{configuration["SpaUrl"]}/logout/callback",
                    $"{configuration["GlobalUrl"]}/logout/callback",
                },

                AllowedCorsOrigins = { configuration["SpaUrl"], configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"] },

                RequirePkce = true,
                RequireConsent = false,

                AllowAccessTokensViaBrowser = true,

                AllowedScopes = { "openid", "profile", "spa", "catalog.bff", "basket.bff" },
            },
            new Client
            {
                ClientId = "catalogswaggerui",
                ClientName = "Catalog Swagger UI",

                AllowedGrantTypes = GrantTypes.Implicit,

                AllowAccessTokensViaBrowser = true,

                RedirectUris = { $"{configuration["CatalogApi"]}/swagger/oauth2-redirect.html" },

                PostLogoutRedirectUris = { $"{configuration["CatalogApi"]}/swagger/" },

                AllowedCorsOrigins = { configuration["SpaUrl"], configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"] },

                AllowedScopes = { "spa", "catalog", "catalog.bff" },
            },
            new Client
            {
                ClientId = "basketswaggerui",
                ClientName = "Basket Swagger UI",

                AllowedGrantTypes = GrantTypes.Implicit,

                AllowAccessTokensViaBrowser = true,

                RedirectUris = { $"{configuration["BasketApi"]}/swagger/oauth2-redirect.html" },

                PostLogoutRedirectUris = { $"{configuration["BasketApi"]}/swagger/" },

                AllowedCorsOrigins = { configuration["SpaUrl"], configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"] },

                AllowedScopes = { "spa", "basket", "basket.bff" },
            },
        };
    }
}
