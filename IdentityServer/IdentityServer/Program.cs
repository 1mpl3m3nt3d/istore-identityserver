// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.IO;

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

namespace IdentityServer
{
    public class Program
    {
        public static int Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                .Enrich.FromLogContext()
                // uncomment to write to Azure diagnostics stream
                //.WriteTo.File(
                //    @"D:\home\LogFiles\Application\identityserver.txt",
                //    fileSizeLimitBytes: 1_000_000,
                //    rollOnFileSizeLimit: true,
                //    shared: true,
                //    flushToDiskInterval: TimeSpan.FromSeconds(1))
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateLogger();

            Log.Information("Starting host...");

            var builder = CreateHostBuilder(args);

            try
            {
                if (Environment.GetEnvironmentVariable("Nginx__UseNginx") == "true")
                {
                    try
                    {
                        if (Environment.GetEnvironmentVariable("Nginx__UseInitFile") == "true")
                        {
                            var initFile = Environment.GetEnvironmentVariable("Nginx__InitFilePath") ?? "/tmp/app-initialized";

                            if (!File.Exists(initFile))
                            {
                                File.Create(initFile).Close();
                            }

                            File.SetLastWriteTimeUtc(initFile, DateTime.UtcNow);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warning($"Environment variable <Nginx__UseNginx> is set to 'true', but there was an exception while configuring Initialize File:\n{ex.Message}");
                    }

                    try
                    {
                        if (Environment.GetEnvironmentVariable("Nginx__UseUnixSocket") == "true")
                        {
                            var unixSocket = Environment.GetEnvironmentVariable("Nginx__UnixSocketPath") ?? "/tmp/nginx.socket";

                            builder.ConfigureWebHostDefaults(webBuilder => webBuilder.ConfigureKestrel(kestrel => kestrel.ListenUnixSocket(unixSocket)));
                        }
                        else
                        {
                            var portParsed = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var port);

                            if (portParsed)
                            {
                                builder.ConfigureWebHostDefaults(webBuilder => webBuilder.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port)));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warning($"Environment variable <Nginx__UseNginx> is set to 'true', but there was an exception while configuring Kestrel:\n{ex.Message}");
                    }
                }
                else
                {
                    var portEnv = Environment.GetEnvironmentVariable("PORT");

                    try
                    {
                        if (Environment.GetEnvironmentVariable("PORT") != null)
                        {
                            var portParsed = int.TryParse(portEnv, out var port);

                            if (portParsed)
                            {
                                builder.ConfigureWebHostDefaults(webBuilder => webBuilder.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port)));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warning($"Environment variable <PORT> is set to '{portEnv}', but there was an exception while configuring Kestrel:\n{ex.Message}");
                    }
                }

                try
                {
                    builder.Build().Run();
                }
                catch (Exception ex)
                {
                    Log.Warning($"There was an exception while running an app:\n{ex.Message}");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly!");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)
                .UseSerilog()
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
        }
    }
}
