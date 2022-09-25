// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net;

using IdentityServer4.Extensions;

using IdentityServerHost.Quickstart.UI;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using Serilog;

namespace IdentityServer
{
    public class Startup
    {
        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public IWebHostEnvironment Environment { get; }

        public IConfiguration Configuration { get; }

        public void Configure(IApplicationBuilder app)
        {
            app.UseSerilogRequestLogging();

            app.Use(async (ctx, next) =>
            {
                var identityUri = new Uri(Configuration["IdentityUrl"]);

                var identityUrl =
                    $"{identityUri.Scheme}://{identityUri.Host}{(identityUri.IsDefaultPort ? string.Empty : $":{identityUri.Port}")}";

                var identityHost =
                    $"{identityUri.Host}{(identityUri.IsDefaultPort ? string.Empty : $":{identityUri.Port}")}";

                if (identityUri != null)
                {
                    ctx.Request.Scheme = identityUri.Scheme;
                    ctx.Request.Host = new HostString(identityHost);
                }

                ctx.SetIdentityServerOrigin(identityUrl);

                await next();
            });

            var forwardedHeadersOptions = new ForwardedHeadersOptions()
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto,
                ForwardLimit = 2,
                RequireHeaderSymmetry = false,
            };

            forwardedHeadersOptions.KnownNetworks.Clear();
            forwardedHeadersOptions.KnownProxies.Clear();

            app.UseForwardedHeaders(forwardedHeadersOptions);

            //app.UseCertificateForwarding();

            if (System.Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Production")
            {
                app.UseExceptionHandler("/Error");

                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
                app.UseHttpsRedirection();
            }
            else
            {
                app.UseDeveloperExceptionPage();
            }

            //app.UseDefaultFiles();
            app.UseStaticFiles();

            var cookiePolicyOptions = new CookiePolicyOptions()
            {
                HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None,
                MinimumSameSitePolicy = SameSiteMode.Unspecified,
                Secure = CookieSecurePolicy.SameAsRequest,
            };

            app.UseCookiePolicy(cookiePolicyOptions);

            app.UseRouting();

            // app.UseRequestLocalization();

            app.UseCors("CorsPolicy");

            app.UseIdentityServer();
            app.UseAuthentication();
            app.UseAuthorization();

            // app.UseSession();
            // app.UseResponseCompression();
            // app.UseResponseCaching();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
                //endpoints.MapRazorPages();
            });
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            var configuration = new ConfigurationBuilder()
            .SetBasePath(baseDirectory)
            .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
            .AddEnvironmentVariables()
            .Build();

            services.Configure<AppSettings>(configuration);

            services.Configure<ForwardedHeadersOptions>(options =>
                {
                    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto;
                    options.ForwardLimit = 2;
                    options.RequireHeaderSymmetry = false;

                    options.KnownNetworks.Clear();
                    options.KnownProxies.Clear();
                });

            //services.AddRazorPages();

            services.AddControllersWithViews();

            //services.AddCertificateForwarding(options => { });

            services.AddHsts(options =>
                {
                    options.IncludeSubDomains = true;
                    options.MaxAge = TimeSpan.FromDays(60);
                    options.Preload = true;
                });

            services.AddHttpsRedirection(options =>
                {
                    options.RedirectStatusCode = (int)HttpStatusCode.TemporaryRedirect;

                    var isPortParsed = int.TryParse(configuration["HTTPS_PORT"], out var httpsPort);

                    if (isPortParsed)
                    {
                        options.HttpsPort = httpsPort;
                    }
                });

            /*
            services.ConfigureApplicationCookie(options =>
                {
                    options.Cookie.HttpOnly = false;
                    options.Cookie.Expiration = TimeSpan.FromDays(30);
                    options.Cookie.SameSite = SameSiteMode.Unspecified;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    options.ExpireTimeSpan = TimeSpan.FromDays(30);
                    options.SlidingExpiration = true;
                });

            services.ConfigureExternalCookie(options =>
                {
                    options.Cookie.HttpOnly = false;
                    options.Cookie.Expiration = TimeSpan.FromDays(30);
                    options.Cookie.SameSite = SameSiteMode.Unspecified;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    options.ExpireTimeSpan = TimeSpan.FromDays(30);
                    options.SlidingExpiration = true;
                });
            */

            services.AddCors(options =>
                options.AddPolicy(
                    "CorsPolicy",
                    corsBuilder => corsBuilder
                        .SetIsOriginAllowed((host) => true)
                        .WithOrigins(
                            configuration["BasketApi"],
                            configuration["CatalogApi"],
                            configuration["GlobalUrl"],
                            configuration["IdentityUrl"],
                            configuration["SpaUrl"])
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials()));

            var isBuilder = services.AddIdentityServer(options =>
                {
                    //options.Authentication.CookieAuthenticationScheme = IdentityServerConstants.DefaultCookieAuthenticationScheme;
                    //options.Authentication.CookieLifetime = TimeSpan.FromDays(30);
                    //options.Authentication.CookieSameSiteMode = SameSiteMode.Unspecified;
                    //options.Authentication.CookieSlidingExpiration = true;
                    //options.Authentication.CoordinateClientLifetimesWithUserSession = false;
                    //options.Authentication.RequireAuthenticatedUserForSignOutMessage = true;
                    //options.Authentication.RequireCspFrameSrcForSignout = false;

                    //options.Cors.CorsPolicyName = "CorsPolicy";

                    //options.Csp.AddDeprecatedHeader = true;
                    //options.Csp.Level = CspLevel.One;

                    // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                    options.EmitStaticAudienceClaim = true;
                    //options.EmitStateHash = true;

                    options.Events.RaiseErrorEvents = true;
                    options.Events.RaiseFailureEvents = true;
                    options.Events.RaiseInformationEvents = true;
                    options.Events.RaiseSuccessEvents = true;

                    //options.IssuerUri = configuration["IdentityUrl"];

                    // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/keys/
                    //options.KeyManagement.Enabled = true;
                    //options.KeyManagement.PropagationTime = TimeSpan.FromDays(2);
                    //options.KeyManagement.RetentionDuration = TimeSpan.FromDays(7);
                    //options.KeyManagement.RotationInterval = TimeSpan.FromDays(30);

                    //options.StrictJarValidation = false;

                    //options.ValidateTenantOnAuthorization = false;
                })
            .AddTestUsers(TestUsers.Users);

            // in-memory, code config
            isBuilder.AddInMemoryIdentityResources(Config.IdentityResources);
            isBuilder.AddInMemoryApiScopes(Config.ApiScopes);
            isBuilder.AddInMemoryClients(Config.Clients(configuration));

            // not recommended for production - you need to store your key material somewhere secure
            isBuilder.AddDeveloperSigningCredential();

            // if you want to use server-side sessions: https://blog.duendesoftware.com/posts/20220406_session_management/
            // then enable it
            //isBuilder.AddServerSideSessions();
            //
            // and put some authorization on the admin/management pages
            //builder.Services.AddAuthorization(options =>
            //       options.AddPolicy("admin",
            //           policy => policy.RequireClaim("sub", "1"))
            //   );
            //builder.Services.Configure<RazorPagesOptions>(options =>
            //    options.Conventions.AuthorizeFolder("/ServerSideSessions", "admin"));

            /*
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = IdentityServerConstants.DefaultCookieAuthenticationScheme;
                options.RequireAuthenticatedSignIn = false;
            });

            /*
            .AddGoogle(options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                // register your IdentityServer with Google at https://console.developers.google.com
                // enable the Google+ API
                // set the redirect URI to https://localhost:5001/signin-google
                options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
                options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
            })
            .AddOpenIdConnect("oidc", "IdentityServer", options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.SaveTokens = true;

                options.Authority = builder.Configuration["Authentication:Oidc:Authority"];
                options.ClientId = "interactive.confidential";
                options.ClientSecret = "secret";
                options.ResponseType = "code";

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            });
            */
        }
    }
}
