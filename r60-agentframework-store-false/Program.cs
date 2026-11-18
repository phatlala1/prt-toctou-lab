using System.Runtime.CompilerServices;

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

var app = builder.Build();
app.MapGet("/ready", () => Results.Ok(new { ready = true }));
app.MapOpenAIResponses();
app.Run();

internal sealed class FixedChatClient : IChatClient
{
    private static readonly ChatClientMetadata s_metadata =
        new("R60FixedChatClient", new Uri("http://127.0.0.1/owned-lab"), "synthetic-model");

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(
            new ChatResponse(new ChatMessage(ChatRole.Assistant, "R60_SYNTHETIC_RESPONSE")));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        yield return new ChatResponseUpdate(ChatRole.Assistant, "R60_SYNTHETIC_RESPONSE");
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
