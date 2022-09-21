using System.Net;

using Duende.IdentityServer.Services;

using IdentityServerHost;

using Microsoft.AspNetCore.HttpOverrides;

using Serilog;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder, IConfiguration? configuration = null)
    {
        builder.Services.AddRazorPages();

        if (configuration is not null)
        {
            builder.Services.Configure<AppSettings>(configuration);
        }

        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            options.RequireHeaderSymmetry = false;
        });

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

        if (!builder.Environment.IsDevelopment() && builder.Configuration["Nginx:UseNginx"] != "true")
        {
            builder.Services.AddHsts(options =>
            {
                options.Preload = true;
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(60);
            });

            var isPortParsed = int.TryParse(builder.Configuration["HTTPS_PORT"], out var httpsPort);

            builder.Services.AddHttpsRedirection(options =>
            {
                options.RedirectStatusCode = (int)HttpStatusCode.TemporaryRedirect;

                if (isPortParsed)
                {
                    options.HttpsPort = httpsPort;
                }
            });
        }

        var isBuilder = builder.Services.AddIdentityServer(options =>
            {
                options.Authentication.CookieSameSiteMode = SameSiteMode.Unspecified;
                options.Authentication.CookieSlidingExpiration = true;
                options.Authentication.CookieLifetime = TimeSpan.FromDays(30);

                options.Cors.CorsPolicyName = "CorsPolicy";

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

        builder.Services.ConfigureApplicationCookie(
            options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromDays(30);
                options.SlidingExpiration = true;
            });

        builder.ConfigureNginx();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
        }

        app.UseForwardedHeaders();

        if (app.Configuration["Nginx:UseNginx"] != "true")
        {
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
            app.UseHttpsRedirection();
        }

        app.Use(async (ctx, next) =>
        {
            var identityUri = new Uri(app.Configuration["IdentityUrl"]);
            var identityUrl = $"{identityUri.Scheme}://{identityUri.Host}{(identityUri.IsDefaultPort ? string.Empty : $":{identityUri.Port}")}";

            if (identityUri is not null && identityUrl is not null)
            {
                var contextUrls = ctx.RequestServices.GetService<IServerUrls>();

                if (contextUrls is not null)
                {
                    contextUrls.Origin = identityUrl;
                }

                //ctx.Request.Scheme = identityUri.Scheme;
                //ctx.Request.Host = new HostString(identityUri.Host);
            }

            await next(ctx);
        });

        app.UseStaticFiles();

        app.UseCookiePolicy(
            new CookiePolicyOptions
            {
                HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None,
                MinimumSameSitePolicy = SameSiteMode.Unspecified,
                Secure = CookieSecurePolicy.SameAsRequest,
            });

        app.UseRouting();

        //app.UseRequestLocalization();

        app.UseCors("CorsPolicy");

        app.UseCertificateForwarding();
        app.UseAuthentication();

        app.UseIdentityServer();
        app.UseAuthorization();

        //app.UseSession();
        //app.UseResponseCompression();
        //app.UseResponseCaching();

        app.MapRazorPages()
            .RequireAuthorization();

        app.UseEndpoints(
            endpoints =>
            endpoints.MapDefaultControllerRoute());

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
