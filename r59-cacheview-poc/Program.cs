using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorComponents();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Owned, synthetic identities only. The collision route deliberately models a
// principal whose primary authenticated identity has no NameIdentifier while a
// secondary identity contributes a shared NameIdentifier. The control route
// gives the primary identity its own unique NameIdentifier.
app.Use(async (context, next) =>
{
    var userName = context.Request.Query["u"].ToString();
    if (string.IsNullOrWhiteSpace(userName))
    {
        userName = "anonymous-test-user";
    }

    var primary = new ClaimsIdentity("PrimaryAuth", ClaimTypes.Name, ClaimTypes.Role);
    primary.AddClaim(new Claim(ClaimTypes.Name, userName, ClaimValueTypes.String, "primary-issuer"));

    if (context.Request.Path.StartsWithSegments("/control"))
    {
        primary.AddClaim(new Claim(ClaimTypes.NameIdentifier, userName, ClaimValueTypes.String, "primary-issuer"));
    }

    var auxiliary = new ClaimsIdentity("AuxiliaryAuth");
    auxiliary.AddClaim(new Claim(ClaimTypes.NameIdentifier, "shared-auxiliary-id", ClaimValueTypes.String, "auxiliary-issuer"));

    context.User = new ClaimsPrincipal([primary, auxiliary]);
    await next(context);
});

app.MapRazorComponents<App>();
app.Run();
