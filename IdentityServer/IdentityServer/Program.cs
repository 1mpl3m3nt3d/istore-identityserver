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

            try
            {
                Log.Information("Starting host...");

                var builder = CreateHostBuilder(args);

                if (Environment.GetEnvironmentVariable("HEROKU_NGINX") == "true")
                {
                    try
                    {
                        var initFile = Environment.GetEnvironmentVariable("InitializedFile") ?? "/tmp/app-initialized";

                        if (!File.Exists(initFile))
                        {
                            File.Create(initFile).Close();
                        }

                        File.SetLastWriteTimeUtc(initFile, DateTime.UtcNow);
                    }
                    catch (Exception ex)
                    {
                        Log.Warning($"Environment variable <HEROKU_NGINX> is set to <TRUE>, but there was an exception:\n{ex.Message}");
                    }

                    try
                    {
                        var socket = Environment.GetEnvironmentVariable("LinuxSocket") ?? "/tmp/nginx.socket";

                        builder.ConfigureWebHostDefaults(webBuilder => webBuilder.ConfigureKestrel(kestrel => kestrel.ListenUnixSocket(socket)));

                        builder.Build().Run();
                    }
                    catch (Exception ex)
                    {
                        Log.Warning($"Environment variable <HEROKU_NGINX> is set to <TRUE>, but there was an exception while configuring Kestrel for Listening Unix Socket:\n{ex.Message}");
                    }
                }
                else
                {
                    if (Environment.GetEnvironmentVariable("PORT") != null)
                    {
                        try
                        {
                            var parsed = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var port);

                            if (parsed)
                            {
                                builder.ConfigureWebHostDefaults(webBuilder => webBuilder.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port)));

                                builder.Build().Run();
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Warning($"Environment variable <PORT> is set, but there was an exception while configuring Kestrel for Listening Port:\n{ex.Message}");
                        }
                    }
                    else
                    {
                        CreateHostBuilder(args).Build().Run();
                    }
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
