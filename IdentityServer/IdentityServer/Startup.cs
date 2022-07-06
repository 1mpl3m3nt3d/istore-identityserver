// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.IO;

using IdentityServer4.Extensions;

using IdentityServerHost.Quickstart.UI;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

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
            // ref: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-6.0#middleware-order
            // ref: https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-6.0
            // ref: https://github.com/aspnet/Docs/issues/2384
            // ref: https://github.com/IdentityServer/IdentityServer4/issues/1331
            // ref: https://github.com/IdentityServer/IdentityServer4/issues/4535
            // ref: https://stackoverflow.com/questions/69048286/non-https-url-in-identity-server-4-discovery-document
            // ref: https://identityserver4.readthedocs.io/en/latest/topics/mtls.html?highlight=proxy#asp-net-core-setup

            app.Use(async (ctx, next) =>
            {
                ctx.SetIdentityServerOrigin(Configuration["IdentityUrl"]);

                // ctx.Request.Scheme = "https";
                // ctx.Request.Host = new HostString("foo.com");

                await next();
            });

            // Add the ForwardedHeadersOptions that you want.
            // By default the options are empty, so you MUST specify what you want.
            var forwardOptions = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                RequireHeaderSymmetry = false,
            };

            // Clear the forward headers networks so any ip can forward headers
            // Should ONLY do this in dev/testing
            // options.KnownNetworks.Clear();
            // options.KnownProxies.Clear();

            // For security you should limit the networks that can forward headers
            // Adding a network with a mask
            // forwardOptions.KnownNetworks.Add(new IPNetwork(IPAddress.Parse("::ffff:111.11.1.0"), 16));
            // OR adding specific ips
            // forwardOptions.KnownProxies.Add(IPAddress.Parse("::ffff:101.1.0.1"));

            app.UseForwardedHeaders(forwardOptions);

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

            app.UseStaticFiles();

            app.UseCookiePolicy(
                new CookiePolicyOptions
                {
                    HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None,
                    MinimumSameSitePolicy = SameSiteMode.Unspecified,
                    Secure = CookieSecurePolicy.SameAsRequest,
                });

            app.UseRouting();

            // app.UseRequestLocalization();

            app.UseCors("CorsPolicy");

            app.UseIdentityServer();

            app.UseAuthentication();
            app.UseAuthorization();

            // app.UseSession();
            // app.UseResponseCompression();
            // app.UseResponseCaching();

            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables().Build();

            services.Configure<AppSettings>(configuration);

            services.AddCors(
                options => options
                .AddPolicy(
                    "CorsPolicy",
                    builder => builder
                    .SetIsOriginAllowed((host) => true)
                    .WithOrigins(configuration["SpaUrl"], configuration["BasketApi"], configuration["CatalogApi"], configuration["GlobalUrl"], configuration["IdentityUrl"])
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials()));

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                options.EmitStaticAudienceClaim = true;
            });

            builder.AddTestUsers(TestUsers.Users);

            // in-memory, code config
            builder.AddInMemoryIdentityResources(Config.GetIdentityResources());
            //builder.AddInMemoryApiResources(Config.GetApiResources());
            builder.AddInMemoryApiScopes(Config.GetApiScopes());
            builder.AddInMemoryClients(Config.GetClients(configuration));

            // not recommended for production - you need to store your key material somewhere secure
            builder.AddDeveloperSigningCredential();

            /*
            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    // register your IdentityServer with Google at https://console.developers.google.com
                    // enable the Google+ API
                    // set the redirect URI to https://localhost:5001/signin-google
                    options.ClientId = "copy client ID from Google here";
                    options.ClientSecret = "copy client secret from Google here";
                });
            */
        }
    }
}
