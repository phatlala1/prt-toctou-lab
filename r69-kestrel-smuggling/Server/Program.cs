using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
});

var app = builder.Build();
var logPath = Environment.GetEnvironmentVariable("R69_BACKEND_LOG")
    ?? Path.Combine(AppContext.BaseDirectory, "r69-backend.jsonl");
var gate = new object();

app.Run(async context =>
{
    byte[] body;
    await using (var buffer = new MemoryStream())
    {
        await context.Request.Body.CopyToAsync(buffer);
        body = buffer.ToArray();
    }

    var record = JsonSerializer.Serialize(new
    {
        timestampUtc = DateTimeOffset.UtcNow,
        method = context.Request.Method,
        path = context.Request.Path.Value,
        query = context.Request.QueryString.Value,
        protocol = context.Request.Protocol,
        host = context.Request.Host.Value,
        contentLength = context.Request.ContentLength,
        transferEncoding = context.Request.Headers.TransferEncoding.ToString(),
        connection = context.Request.Headers.Connection.ToString(),
        bodyLength = body.Length,
        bodyPrefixHex = Convert.ToHexString(body.AsSpan(0, Math.Min(body.Length, 96))).ToLowerInvariant(),
        remoteIp = context.Connection.RemoteIpAddress?.ToString(),
        remotePort = context.Connection.RemotePort,
        connectionId = context.Connection.Id,
    });

    lock (gate)
    {
        File.AppendAllText(logPath, record + Environment.NewLine);
    }

    context.Response.StatusCode = StatusCodes.Status200OK;
    context.Response.ContentType = "text/plain";
    await context.Response.WriteAsync($"R69 {context.Request.Method} {context.Request.Path}\n", Encoding.UTF8);
});

app.Run();
