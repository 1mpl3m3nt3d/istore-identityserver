using System.Net;

using Duende.IdentityServer.Services;

using IdentityServerHost;

using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.HttpOverrides;

using Serilog;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder, IConfiguration? configuration = null)
    {
        builder.Services.AddRazorPages();

        builder.Services.AddCertificateForwarding(options => { });

        if (configuration is not null)
        {
            builder.Services.Configure<AppSettings>(configuration);
        }

        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 2;
            options.RequireHeaderSymmetry = false;
        });

        builder.Services.Configure<CookiePolicyOptions>(options =>
        {
            options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None;
            options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            options.Secure = CookieSecurePolicy.SameAsRequest;
        });

        builder.Services.ConfigureApplicationCookie(
            options =>
            {
                options.Cookie.HttpOnly = false;
                options.Cookie.Expiration = TimeSpan.FromDays(30);
                options.Cookie.SameSite = SameSiteMode.Unspecified;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.ExpireTimeSpan = TimeSpan.FromDays(30);
                options.SlidingExpiration = true;
            });

        builder.Services.ConfigureExternalCookie(
            options =>
            {
                options.Cookie.HttpOnly = false;
                options.Cookie.Expiration = TimeSpan.FromDays(30);
                options.Cookie.SameSite = SameSiteMode.Unspecified;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.ExpireTimeSpan = TimeSpan.FromDays(30);
                options.SlidingExpiration = true;
            });

        builder.Services.AddCookiePolicy(options =>
        {
            options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None;
            options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            options.Secure = CookieSecurePolicy.SameAsRequest;
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

        //if (!builder.Environment.IsDevelopment() && builder.Configuration["Nginx:UseNginx"] != "true")
        //{
        builder.Services.AddHsts(options =>
        {
            options.IncludeSubDomains = true;
            options.MaxAge = TimeSpan.FromDays(60);
            options.Preload = true;
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
        //}

        var isBuilder = builder.Services.AddIdentityServer(options =>
            {
                options.Authentication.CookieLifetime = TimeSpan.FromDays(30);
                options.Authentication.CookieSameSiteMode = SameSiteMode.Unspecified;
                options.Authentication.CookieSlidingExpiration = true;

                options.Cors.CorsPolicyName = "CorsPolicy";

                options.Csp.AddDeprecatedHeader = true;
                options.Csp.Level = Duende.IdentityServer.Models.CspLevel.One;

                options.IssuerUri = builder.Configuration["IdentityUrl"];

                options.StrictJarValidation = false;
                options.ValidateTenantOnAuthorization = false;

                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseInformationEvents = true;
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

        builder.Services.AddHttpLogging(options =>
        {
            options.LoggingFields = HttpLoggingFields.RequestScheme | HttpLoggingFields.RequestPropertiesAndHeaders | HttpLoggingFields.ResponsePropertiesAndHeaders;
        });

        builder.ConfigureNginx();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        app.UseCertificateForwarding();

        var forwardedHeadersOptions = new ForwardedHeadersOptions()
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 2,
            RequireHeaderSymmetry = false,
        };

        forwardedHeadersOptions.KnownNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();

        app.UseForwardedHeaders(forwardedHeadersOptions);

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");

            //if (app.Configuration["Nginx:UseNginx"] != "true")
            //{
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
            //}
        }

        app.UseHttpLogging();

        app.Use(async (context, next) =>
        {
            app.Logger.LogInformation(
                "Request RemoteIp: {RemoteIpAddress}",
                context.Connection.RemoteIpAddress);

            await next(context);
        });

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

                var requestUrls = ctx.Request.HttpContext.RequestServices.GetService<IServerUrls>();

                if (requestUrls is not null)
                {
                    requestUrls.Origin = identityUrl;
                }

                var responseUrls = ctx.Response.HttpContext.RequestServices.GetService<IServerUrls>();

                if (responseUrls is not null)
                {
                    responseUrls.Origin = identityUrl;
                }

                ctx.Request.Scheme = identityUri.Scheme;
                ctx.Request.Host = new HostString($"{identityUri.Host}{(identityUri.IsDefaultPort ? string.Empty : $":{identityUri.Port}")}");
            }

            await next(ctx);
        });

        //if (app.Configuration["Nginx:UseNginx"] != "true")
        //{
        app.UseHttpsRedirection();
        //}

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

        //app.UseRequestLocalization();

        app.UseCors("CorsPolicy");

        app.UseIdentityServer();
        app.UseAuthorization();
        app.UseAuthentication();

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
