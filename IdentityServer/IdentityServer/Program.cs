using IdentityServer;

using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up ...");

try
{
    var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions() { ContentRootPath = baseDirectory });

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
        .Enrich.FromLogContext()
        .ReadFrom.Configuration(ctx.Configuration));

    var configuration = new ConfigurationBuilder()
    .SetBasePath(baseDirectory)
    .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables()
    .AddCommandLine(args)
    .Build();

    var app = builder
        .ConfigureServices(configuration)
        .ConfigurePipeline();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception!");
}
finally
{
    Log.Information("Shut down complete!");
    Log.CloseAndFlush();
}
