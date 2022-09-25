using System;
using System.IO;

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace IdentityServer
{
    internal static class HostingExtensions
    {
        public static IHostBuilder ConfigureNginx(this IHostBuilder builder)
        {
            var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            var configuration = new ConfigurationBuilder()
            .SetBasePath(baseDirectory)
            .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
            .AddEnvironmentVariables()
            .Build();

            if (configuration["Nginx:UseNginx"] == "true")
            {
                try
                {
                    if (configuration["Nginx:UseInitFile"] == "true")
                    {
                        var initFile = configuration["Nginx:InitFilePath"] ?? "/tmp/app-initialized";

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
                    if (configuration["Nginx:UseUnixSocket"] == "true")
                    {
                        var unixSocket = configuration["Nginx:UnixSocketPath"] ?? "/tmp/nginx.socket";

                        builder.ConfigureWebHostDefaults(webBuilder =>
                            webBuilder.ConfigureKestrel(kestrel =>
                                {
                                    kestrel.ListenUnixSocket(unixSocket);
                                    //kestrel.AllowAlternateSchemes = true;
                                }));
                    }

                    if (configuration["Nginx:UsePort"] == "true")
                    {
                        var portParsed = int.TryParse(configuration["Nginx:Port"], out var port);

                        if (portParsed)
                        {
                            builder.ConfigureWebHostDefaults(webBuilder =>
                                webBuilder.ConfigureKestrel(kestrel =>
                                    {
                                        kestrel.ListenAnyIP(port);
                                        //kestrel.AllowAlternateSchemes = true;
                                    }));
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
                var portEnv = configuration["PORT"] ?? Environment.GetEnvironmentVariable("PORT");

                try
                {
                    if (portEnv != null)
                    {
                        var portParsed = int.TryParse(portEnv, out var port);

                        if (portParsed)
                        {
                            builder.ConfigureWebHostDefaults(webBuilder =>
                                webBuilder.ConfigureKestrel(kestrel =>
                                    {
                                        kestrel.ListenAnyIP(port);
                                        //kestrel.AllowAlternateSchemes = true;
                                    }));
                        }
                    }
                    else
                    {
                        var identityUrl = configuration["IdentityUrl"];
                        var identityPort = new Uri(identityUrl).Port;

                        builder.ConfigureWebHostDefaults(webBuilder =>
                            webBuilder.ConfigureKestrel(kestrel =>
                                {
                                    kestrel.ListenAnyIP(identityPort);
                                    //kestrel.AllowAlternateSchemes = true;
                                }));
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
}
