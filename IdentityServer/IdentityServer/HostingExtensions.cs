using System;
using System.IO;

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace IdentityServer
{
    internal static class HostingExtensions
    {
        public static IWebHostBuilder AddNginxConfiguration(this IWebHostBuilder builder, IConfiguration configuration = null)
        {
            if (configuration == null)
            {
                var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

                configuration = new ConfigurationBuilder()
                    .SetBasePath(baseDirectory)
                    .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
                    .AddEnvironmentVariables()
                    .AddCommandLine(Environment.GetCommandLineArgs())
                    .Build();
            }

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

                        builder.ConfigureKestrel(kestrel =>
                            {
                                kestrel.ListenUnixSocket(unixSocket);
                            });
                    }

                    if (configuration["Nginx:UsePort"] == "true")
                    {
                        var portParsed = int.TryParse(configuration["Nginx:Port"], out var port);

                        if (portParsed)
                        {
                            builder.ConfigureKestrel(kestrel =>
                                {
                                    kestrel.ListenAnyIP(port);
                                });
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
                            builder.ConfigureKestrel(kestrel =>
                                {
                                    kestrel.ListenAnyIP(port);
                                });
                        }
                    }
                    else
                    {
                        var identityUrl = configuration["IdentityUrl"];

                        if (identityUrl != null)
                        {
                            try
                            {
                                var identityPort = new Uri(identityUrl)?.Port;

                                if (identityPort is int @port)
                                {
                                    builder.ConfigureKestrel(kestrel =>
                                        {
                                            kestrel.ListenAnyIP(@port);
                                        });
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"There was an exception while configuring Kestrel:\n{ex.Message}");
                            }
                        }
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
