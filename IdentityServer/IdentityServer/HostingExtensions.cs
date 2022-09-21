using Duende.IdentityServer.Services;

using IdentityServerHost;

using Microsoft.AspNetCore.HttpOverrides;

using Serilog;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder, IConfiguration? configuration = null)
    {
        if (configuration is not null)
        {
            //builder.Configuration.AddConfiguration(configuration);
            builder.Services.Configure<AppSettings>(configuration);
        }

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
                options.Authentication.CookieSameSiteMode = SameSiteMode.Unspecified;
                options.Cors.CorsPolicyName = "CorsPolicy";

                options.IssuerUri = builder.Configuration["IdentityUrl"];

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

        builder.ConfigureNginx();

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

        app.Use(async (ctx, next) =>
        {
            var identityUri = new Uri(app.Configuration["IdentityUrl"]);

            if (identityUri is not null)
            {
                ctx.Request.Scheme = identityUri.Scheme + "://";
                ctx.Request.Host = new HostString(identityUri.Host);

                var requestUrls = ctx.Request.HttpContext.RequestServices.GetService<IServerUrls>();

                if (requestUrls is not null)
                {
                    requestUrls.Origin = identityUri.Scheme + "://" + identityUri.Host + identityUri.Port;
                }

                var responseUrls = ctx.Response.HttpContext.RequestServices.GetService<IServerUrls>();

                if (responseUrls is not null)
                {
                    responseUrls.Origin = identityUri.Scheme + "://" + identityUri.Host + identityUri.Port;
                }

                //ctx.SetIdentityServerOrigin(identityUri.Scheme + "://" + identityUri.Host + identityUri.Port);
            }

            await next();
        });

        // Add the ForwardedHeadersOptions that you want.
        // By default the options are empty, so you MUST specify what you want.
        var forwardOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto,
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

    public static WebApplicationBuilder ConfigureNginx(this WebApplicationBuilder builder)
    {
        if (builder.Configuration["Nginx:UseNginx"] == "true")
        {
            try
            {
                if (builder.Configuration["Nginx:UseInitFile"] == "true")
                {
                    var initFile = builder.Configuration["Nginx:InitFilePath"] ?? "/tmp/app-initialized";

                    if (!File.Exists(initFile))
                    {
                        File.Create(initFile).Close();
                    }

                    File.SetLastWriteTimeUtc(initFile, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Variable <UseNginx> is set to 'true', but there was an exception while configuring Initialize File:\n{ex.Message}");
            }

            try
            {
                if (builder.Configuration["Nginx:UseUnixSocket"] == "true")
                {
                    var unixSocket = builder.Configuration["Nginx:UnixSocketPath"] ?? "/tmp/nginx.socket";

                    builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenUnixSocket(unixSocket));
                }

                if (builder.Configuration["Nginx:UsePort"] == "true")
                {
                    var portParsed = int.TryParse(builder.Configuration["Nginx:Port"], out var port);

                    if (portParsed)
                    {
                        builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Variable <UseNginx> is set to 'true', but there was an exception while configuring Kestrel:\n{ex.Message}");
            }
        }
        else
        {
            var portEnv = builder.Configuration["PORT"] ?? Environment.GetEnvironmentVariable("PORT");

            try
            {
                if (portEnv != null)
                {
                    var portParsed = int.TryParse(portEnv, out var port);

                    if (portParsed)
                    {
                        builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port));
                    }
                }
                else
                {
                    var identityUrl = builder.Configuration["IdentityUrl"];
                    var identityPort = new Uri(identityUrl).Port;

                    builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(identityPort));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Variable <PORT> is set to '{portEnv}', but there was an exception while configuring Kestrel:\n{ex.Message}");
            }
        }

        return builder;
    }
}
