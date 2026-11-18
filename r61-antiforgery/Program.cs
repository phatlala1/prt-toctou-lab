using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Primitives;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-R61-CSRF";
});

var app = builder.Build();
app.UseAntiforgery();

var evidencePath = Environment.GetEnvironmentVariable("R61_LOG")
    ?? Path.Combine(AppContext.BaseDirectory, "r61-invocations.jsonl");
var evidenceLock = new object();

IResult Hit(string endpoint, object? value)
{
    var record = JsonSerializer.Serialize(new
    {
        timestampUtc = DateTimeOffset.UtcNow,
        endpoint,
        value,
        pid = Environment.ProcessId,
        mode = Environment.GetEnvironmentVariable("R61_MODE") ?? "unknown"
    });

    lock (evidenceLock)
    {
        File.AppendAllText(evidencePath, record + Environment.NewLine);
    }

    return Results.Json(new { invoked = true, endpoint, value });
}

app.MapGet("/health", () => Results.Ok(new { ok = true }));

app.MapGet("/token", (HttpContext context, IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Json(new
    {
        requestToken = tokens.RequestToken,
        headerName = tokens.HeaderName,
        formFieldName = tokens.FormFieldName
    });
});

app.MapGet("/metadata", (EndpointDataSource source) =>
{
    var result = source.Endpoints
        .OfType<RouteEndpoint>()
        .Select(endpoint => new
        {
            route = endpoint.RoutePattern.RawText,
            antiforgery = endpoint.Metadata.GetMetadata<IAntiforgeryMetadata>()?.RequiresValidation
        })
        .OrderBy(item => item.route)
        .ToArray();
    return Results.Json(result);
});

app.MapPost("/fromform-string", ([FromForm] string value) => Hit("fromform-string", value));
app.MapPost("/fromform-int", ([FromForm] int value) => Hit("fromform-int", value));
app.MapPost("/fromform-nullable-int", ([FromForm] int? value) => Hit("fromform-nullable-int", value));
app.MapPost("/fromform-string-array", ([FromForm] string[] value) => Hit("fromform-string-array", value));
app.MapPost("/fromform-guid", ([FromForm] Guid value) => Hit("fromform-guid", value));
app.MapPost("/fromform-stringvalues", ([FromForm] StringValues value) => Hit("fromform-stringvalues", value.ToArray()));
app.MapPost("/form-collection", (IFormCollection form) => Hit("form-collection", form["value"].ToString()));
app.MapPost("/form-file", (IFormFile file) => Hit("form-file", new { file.Name, file.FileName, file.Length }));
app.MapPost("/form-files", (IFormFileCollection files) => Hit("form-files", files.Select(file => new { file.Name, file.FileName, file.Length }).ToArray()));
app.MapPost("/as-parameters", ([AsParameters] FormClassArgs args) => Hit("as-parameters", args.Value));
app.MapPost("/custom-fromform", ([CustomFromForm(Name = "value")] string value) => Hit("custom-fromform", value));
app.MapPost("/derived-fromform", ([DerivedFromForm(Name = "value")] string value) => Hit("derived-fromform", value));

app.Run();

public sealed class FormClassArgs
{
    [FromForm]
    public string Value { get; init; } = string.Empty;
}

[AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public class CustomFromFormAttribute : Attribute, IFromFormMetadata
{
    public string? Name { get; init; }
}

public sealed class DerivedFromFormAttribute : CustomFromFormAttribute
{
}
