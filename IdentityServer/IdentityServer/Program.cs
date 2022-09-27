// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
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
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateBootstrapLogger(); // .CreateLogger() was used by default in IS4

            try
            {
                Log.Information("Starting up...");

                var builder = CreateHostBuilder(args);

                builder.Build().Run();

                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Unhandled exception!");
                return 1;
            }
            finally
            {
                Log.Information("Shut down complete!");
                Log.CloseAndFlush();
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            var configuration = new ConfigurationBuilder()
                .SetBasePath(baseDirectory)
                .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables()
                .AddCommandLine(args)
                .Build();

            return Host.CreateDefaultBuilder(args)
                .UseSerilog((ctx, lc) =>
                    lc.ReadFrom.Configuration(ctx.Configuration))
                .ConfigureWebHostDefaults(webBuilder =>
                    {
                        webBuilder.UseContentRoot(baseDirectory);
                        webBuilder.UseConfiguration(configuration);
                        webBuilder.UseStartup<Startup>();
                        webBuilder.AddNginxConfiguration(configuration);
                    });
        }
    }
}
