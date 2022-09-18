using IdentityServerHost;

using Microsoft.AspNetCore.HttpOverrides;
//using Microsoft.AspNetCore.Mvc.RazorPages;
using Serilog;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddEnvironmentVariables()
            .Build();

        builder.Services.Configure<AppSettings>(configuration);

        builder.Services.AddRazorPages();

        builder.Services.AddCors(
            options => options
            .AddPolicy(
                "CorsPolicy",
                corsBuilder => corsBuilder
                .SetIsOriginAllowed((host) => true)
                .WithOrigins(builder.Configuration["BasketApi"], builder.Configuration["CatalogApi"], builder.Configuration["GlobalUrl"], builder.Configuration["IdentityUrl"], builder.Configuration["SpaUrl"])
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials()));

        var isBuilder = builder.Services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
            })
            .AddTestUsers(TestUsers.Users);

        // in-memory, code config
        isBuilder.AddInMemoryIdentityResources(AccessConfig.IdentityResources);
        isBuilder.AddInMemoryApiScopes(AccessConfig.ApiScopes);
        isBuilder.AddInMemoryClients(AccessConfig.Clients(builder.Configuration));

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

        builder.Services.AddAuthentication();
        /*
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

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        // ref: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-6.0#middleware-order
        // ref: https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-6.0
        // ref: https://github.com/aspnet/Docs/issues/2384
        // ref: https://github.com/IdentityServer/IdentityServer4/issues/1331
        // ref: https://github.com/IdentityServer/IdentityServer4/issues/4535
        // ref: https://stackoverflow.com/questions/69048286/non-https-url-in-identity-server-4-discovery-document
        // ref: https://identityserver4.readthedocs.io/en/latest/topics/mtls.html?highlight=proxy#asp-net-core-setup

        /*
        app.Use(async (ctx, next) =>
        {
            ctx.SetIdentityServerOrigin(app.Configuration["IdentityUrl"]);

            //ctx.Request.Scheme = "https";
            //ctx.Request.Host = new HostString("host.com");

            await next();
        });
        */

        // Add the ForwardedHeadersOptions that you want.
        // By default the options are empty, so you MUST specify what you want.
        var forwardOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            RequireHeaderSymmetry = false,
        };

        // Clear the forward headers networks so any ip can forward headers
        // Should ONLY do this in dev/testing
        //forwardOptions.KnownNetworks.Clear();
        //forwardOptions.KnownProxies.Clear();

        // For security you should limit the networks that can forward headers
        // Adding a network with a mask
        // forwardOptions.KnownNetworks.Add(new IPNetwork(IPAddress.Parse("::ffff:111.11.1.0"), 16));
        // OR adding specific ips
        //forwardOptions.KnownProxies.Add(IPAddress.Parse("::ffff:101.1.0.1"));

        app.UseForwardedHeaders(forwardOptions);

        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
            app.UseHttpsRedirection();
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

        app.UseCors("CorsPolicy");

        app.UseIdentityServer();
        app.UseAuthorization();

        app.MapRazorPages()
            .RequireAuthorization();

        return app;
    }
}
