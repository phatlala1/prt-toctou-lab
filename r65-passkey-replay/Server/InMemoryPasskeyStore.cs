using Microsoft.AspNetCore.Identity;

namespace R65PasskeyReplay.Server;

public sealed class R65User
{
    public required string Id { get; init; }
    public string? UserName { get; set; }
    public string? NormalizedUserName { get; set; }
    public List<UserPasskeyInfo> Passkeys { get; } = [];
}

public sealed class InMemoryPasskeyStore : IUserStore<R65User>, IUserPasskeyStore<R65User>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, R65User> _users = new(StringComparer.Ordinal);

    public InMemoryPasskeyStore(R65User user, UserPasskeyInfo passkey)
    {
        user.Passkeys.Add(ClonePasskey(passkey));
        _users[user.Id] = user;
    }

    public Task<IdentityResult> CreateAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _users[user.Id] = user;
        }
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _users.Remove(user.Id);
        }
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<R65User?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            return Task.FromResult(_users.TryGetValue(userId, out var user) ? user : null);
        }
    }

    public Task<R65User?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            return Task.FromResult(_users.Values.FirstOrDefault(user =>
                string.Equals(user.NormalizedUserName, normalizedUserName, StringComparison.Ordinal)));
        }
    }

    public Task<string?> GetNormalizedUserNameAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.NormalizedUserName);
    }

    public Task<string> GetUserIdAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.Id);
    }

    public Task<string?> GetUserNameAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.UserName);
    }

    public Task SetNormalizedUserNameAsync(R65User user, string? normalizedName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task SetUserNameAsync(R65User user, string? userName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        user.UserName = userName;
        return Task.CompletedTask;
    }

    public Task<IdentityResult> UpdateAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _users[user.Id] = user;
        }
        return Task.FromResult(IdentityResult.Success);
    }

    public Task AddOrUpdatePasskeyAsync(R65User user, UserPasskeyInfo passkey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var existing = user.Passkeys.FirstOrDefault(candidate =>
                candidate.CredentialId.AsSpan().SequenceEqual(passkey.CredentialId));
            if (existing is null)
            {
                user.Passkeys.Add(ClonePasskey(passkey));
            }
            else
            {
                existing.Name = passkey.Name;
                existing.SignCount = passkey.SignCount;
                existing.IsUserVerified = passkey.IsUserVerified;
                existing.IsBackedUp = passkey.IsBackedUp;
                existing.Aaguid = passkey.Aaguid?.ToArray();
            }
        }
        return Task.CompletedTask;
    }

    public Task<IList<UserPasskeyInfo>> GetPasskeysAsync(R65User user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            return Task.FromResult<IList<UserPasskeyInfo>>(user.Passkeys.Select(ClonePasskey).ToList());
        }
    }

    public Task<R65User?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            return Task.FromResult(_users.Values.FirstOrDefault(user =>
                user.Passkeys.Any(passkey => passkey.CredentialId.AsSpan().SequenceEqual(credentialId))));
        }
    }

    public Task<UserPasskeyInfo?> FindPasskeyAsync(R65User user, byte[] credentialId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var passkey = user.Passkeys.FirstOrDefault(candidate =>
                candidate.CredentialId.AsSpan().SequenceEqual(credentialId));
            return Task.FromResult(passkey is null ? null : ClonePasskey(passkey));
        }
    }

    public Task RemovePasskeyAsync(R65User user, byte[] credentialId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var passkey = user.Passkeys.FirstOrDefault(candidate =>
                candidate.CredentialId.AsSpan().SequenceEqual(credentialId));
            if (passkey is not null)
            {
                user.Passkeys.Remove(passkey);
            }
        }
        return Task.CompletedTask;
    }

    public uint GetStoredSignCount(string userId)
    {
        lock (_gate)
        {
            return _users[userId].Passkeys.Single().SignCount;
        }
    }

    public void Dispose()
    {
    }

    private static UserPasskeyInfo ClonePasskey(UserPasskeyInfo source)
        => new(
            source.CredentialId.ToArray(),
            source.PublicKey.ToArray(),
            source.CreatedAt,
            source.SignCount,
            source.Transports?.ToArray(),
            source.IsUserVerified,
            source.IsBackupEligible,
            source.IsBackedUp,
            source.AttestationObject.ToArray(),
            source.ClientDataJson.ToArray())
        {
            Name = source.Name,
            Aaguid = source.Aaguid?.ToArray(),
        };
}
