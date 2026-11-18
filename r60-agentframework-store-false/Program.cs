using System.Runtime.CompilerServices;
using System.Security.Claims;

using Microsoft.Agents.AI.Hosting;
using Microsoft.Extensions.AI;

var builder = WebApplication.CreateBuilder(args);

// Fully local, deterministic chat client. No external model, API key, network
// service, tool invocation, or privileged credential is involved.
builder.Services.AddChatClient(new FixedChatClient());
builder.AddAIAgent(
    name: "assistant",
    instructions: "Return the deterministic synthetic response supplied by the local test client.");
builder.Services.AddOpenAIResponses();
builder.Services.AddOpenAIConversations();
builder.Services.AddHttpContextAccessor();
builder.Services.UseClaimsBasedAgentIsolation();

var app = builder.Build();

// Synthetic owned-lab principal. The header is accepted only to make the two
// authenticated-principal partitions deterministic inside this isolated test.
app.Use(async (context, next) =>
{
    var testUser = context.Request.Headers["X-R61-Test-User"].ToString();
    if (!string.IsNullOrWhiteSpace(testUser))
    {
        var identity = new ClaimsIdentity("R61OwnedLabAuthentication");
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, testUser));
        identity.AddClaim(new Claim(ClaimTypes.Name, testUser));
        context.User = new ClaimsPrincipal(identity);
    }

    await next(context);
});

app.MapGet("/ready", () => Results.Ok(new { ready = true }));
app.MapOpenAIResponses();
app.MapOpenAIConversations();
app.Run();

internal sealed class FixedChatClient : IChatClient
{
    private static readonly ChatClientMetadata s_metadata =
        new("R61FixedChatClient", new Uri("http://127.0.0.1/owned-lab"), "synthetic-model");

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(
            new ChatResponse(new ChatMessage(ChatRole.Assistant, "R61_SYNTHETIC_RESPONSE")));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        yield return new ChatResponseUpdate(ChatRole.Assistant, "R61_SYNTHETIC_RESPONSE");
        await Task.CompletedTask;
    }

    public object? GetService(Type serviceType, object? serviceKey = null) =>
        serviceKey is not null ? null :
        serviceType == typeof(ChatClientMetadata) ? s_metadata :
        serviceType.IsInstanceOfType(this) ? this :
        null;

    public void Dispose()
    {
    }
}
