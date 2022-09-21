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

                ClientUri = $"{configuration["GlobalUrl"]}",

                AllowedGrantTypes = GrantTypes.Code,

                ClientSecrets = { new Secret("secret".Sha256()) },

                RedirectUris =
                {
                    $"{configuration["GlobalUrl"]}/signin-oidc",
                    $"{configuration["GlobalUrl"]}/silentrenew",
                    $"{configuration["GlobalUrl"]}/signout-oidc",
                    $"{configuration["GlobalUrl"]}/logout/callback",
                    $"{configuration["SpaUrl"]}/signin-oidc",
                    $"{configuration["SpaUrl"]}/silentrenew",
                    $"{configuration["SpaUrl"]}/signout-oidc",
                    $"{configuration["SpaUrl"]}/logout/callback",
                },

                PostLogoutRedirectUris =
                {
                    $"{configuration["GlobalUrl"]}/logout/callback",
                    $"{configuration["SpaUrl"]}/logout/callback",
                },

                AllowedCorsOrigins = { configuration["GlobalUrl"], configuration["IdentityUrl"], configuration["SpaUrl"] },

                RequirePkce = true,
                RequireConsent = false,

                AllowAccessTokensViaBrowser = true,

                AllowedScopes = { "openid", "profile", "spa" },
            },
            new Client
            {
                ClientId = "catalogswaggerui",
                ClientName = "Catalog Swagger UI",

                AllowedGrantTypes = GrantTypes.Implicit,

                AllowAccessTokensViaBrowser = true,

                RedirectUris = { $"{configuration["CatalogApi"]}/swagger/oauth2-redirect.html" },

                PostLogoutRedirectUris = { $"{configuration["CatalogApi"]}/swagger/" },

                AllowedCorsOrigins = { configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"] },

                AllowedScopes = { "catalog", "catalog.bff", "openid", "profile", "spa" },
            },
            new Client
            {
                ClientId = "basketswaggerui",
                ClientName = "Basket Swagger UI",

                AllowedGrantTypes = GrantTypes.Implicit,

                AllowAccessTokensViaBrowser = true,

                RedirectUris = { $"{configuration["BasketApi"]}/swagger/oauth2-redirect.html" },

                PostLogoutRedirectUris = { $"{configuration["BasketApi"]}/swagger/" },

                AllowedCorsOrigins = { configuration["BasketApi"], configuration["GlobalUrl"], configuration["IdentityUrl"] },

                AllowedScopes = { "basket", "basket.bff", "openid", "profile", "spa" },
            },
        };
    }
}
