using System.Collections;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

if (args.Length != 4)
{
    Console.Error.WriteLine("usage: ParserProbe <agent-bin> <cases.jsonl> <corpus-stats.json> <result.json>");
    return 2;
}

string agentBin = Path.GetFullPath(args[0]);
string casesPath = Path.GetFullPath(args[1]);
string corpusStatsPath = Path.GetFullPath(args[2]);
string resultPath = Path.GetFullPath(args[3]);
string agentAssemblyPath = Path.Combine(agentBin, "Microsoft.VisualStudio.Services.Agent.dll");
string workerAssemblyPath = Path.Combine(agentBin, "Agent.Worker.dll");

if (!File.Exists(agentAssemblyPath) || !File.Exists(workerAssemblyPath))
{
    Console.Error.WriteLine($"shipping agent assemblies missing under {agentBin}");
    return 2;
}
if (!File.Exists(casesPath) || !File.Exists(corpusStatsPath))
{
    Console.Error.WriteLine("corpus files missing");
    return 2;
}

AssemblyLoadContext.Default.Resolving += (context, name) =>
{
    string candidate = Path.Combine(agentBin, name.Name + ".dll");
    return File.Exists(candidate) ? context.LoadFromAssemblyPath(candidate) : null;
};

Assembly agentAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(agentAssemblyPath);
Assembly workerAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(workerAssemblyPath);
Type commandType = agentAssembly.GetType("Microsoft.VisualStudio.Services.Agent.Command", throwOnError: true)!;
MethodInfo tryParse = commandType.GetMethod(
    "TryParse",
    BindingFlags.Public | BindingFlags.Static,
    binder: null,
    types: [typeof(string), typeof(bool), commandType.MakeByRefType()],
    modifiers: null) ?? throw new MissingMethodException(commandType.FullName, "TryParse");
PropertyInfo areaProperty = commandType.GetProperty("Area")!;
PropertyInfo eventProperty = commandType.GetProperty("Event")!;

var registeredCommands = DiscoverRegisteredCommands(workerAssembly);
registeredCommands.Add("agent.pausecommands");
registeredCommands.Add("agent.resumecommands");
var allowedCommands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "task.debug",
    "task.setprogress",
};

long caseRecords = 0;
long logicalLines = 0;
long parsedLines = 0;
long parsedRegistered = 0;
long parsedAllowed = 0;
long parsedUnknown = 0;
long securityBypasses = 0;
var bypassExamples = new List<object>();
var unknownExamples = new List<object>();
var allowedExamples = new List<object>();

foreach (string jsonLine in File.ReadLines(casesPath, Encoding.UTF8))
{
    if (string.IsNullOrWhiteSpace(jsonLine))
    {
        continue;
    }

    caseRecords++;
    using JsonDocument document = JsonDocument.Parse(jsonLine);
    JsonElement root = document.RootElement;
    string mode = root.GetProperty("mode").GetString() ?? string.Empty;
    string origin = root.GetProperty("origin").GetString() ?? string.Empty;
    string originalB64 = root.GetProperty("originalB64").GetString() ?? string.Empty;
    string filteredB64 = root.GetProperty("filteredB64").GetString() ?? string.Empty;
    string filtered = Encoding.UTF8.GetString(Convert.FromBase64String(filteredB64));

    foreach (string line in EnumerateAgentLines(filtered))
    {
        logicalLines++;
        if (!line.Contains("##vso[", StringComparison.Ordinal))
        {
            continue;
        }

        object?[] invokeArguments = [line, true, null];
        bool parsed;
        try
        {
            parsed = (bool)(tryParse.Invoke(null, invokeArguments) ?? false);
        }
        catch (TargetInvocationException exception)
        {
            throw new InvalidOperationException(
                $"shipping Command.TryParse threw for case {caseRecords}",
                exception.InnerException ?? exception);
        }

        if (!parsed || invokeArguments[2] is null)
        {
            continue;
        }

        parsedLines++;
        object command = invokeArguments[2]!;
        string area = (string?)areaProperty.GetValue(command) ?? string.Empty;
        string eventName = (string?)eventProperty.GetValue(command) ?? string.Empty;
        string commandName = area + "." + eventName;
        bool registered = registeredCommands.Contains(commandName);
        bool allowed = allowedCommands.Contains(commandName);

        if (registered)
        {
            parsedRegistered++;
        }
        else
        {
            parsedUnknown++;
            AddExample(unknownExamples, new
            {
                mode,
                origin,
                commandName,
                line = Escape(line),
                originalB64,
                filteredB64,
            });
        }

        if (allowed)
        {
            parsedAllowed++;
            AddExample(allowedExamples, new
            {
                mode,
                origin,
                commandName,
                line = Escape(line),
            });
        }

        bool bypass = mode switch
        {
            "block" => registered,
            "allowDefault" => registered && !allowed,
            _ => true,
        };

        if (bypass)
        {
            securityBypasses++;
            AddExample(bypassExamples, new
            {
                mode,
                origin,
                commandName,
                line = Escape(line),
                originalB64,
                filteredB64,
            });
        }
    }
}

JsonElement corpusStats;
using (JsonDocument corpusDocument = JsonDocument.Parse(File.ReadAllText(corpusStatsPath, Encoding.UTF8)))
{
    corpusStats = corpusDocument.RootElement.Clone();
}

var result = new
{
    schema = "r83-tasklib-agent-parser-differential/v1",
    status = securityBypasses > 0
        ? "SHIPPING_AGENT_PARSER_BYPASS_REVIEW_REQUIRED"
        : "RUNTIME_NEGATIVE_CLOSED",
    agent = new
    {
        release = "v5.282.0",
        assemblyVersion = agentAssembly.GetName().Version?.ToString(),
        agentAssemblySha256 = Sha256(agentAssemblyPath),
        workerAssemblySha256 = Sha256(workerAssemblyPath),
    },
    corpusStats,
    registeredCommands = registeredCommands.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray(),
    counts = new
    {
        caseRecords,
        logicalLines,
        parsedLines,
        parsedRegistered,
        parsedAllowed,
        parsedUnknown,
        securityBypasses,
    },
    bypassExamples,
    unknownExamples,
    allowedExamples,
    securityClaimLimit = "A positive requires a filtered line parsed as a registered shipping-agent command that was not allowed by the selected sanitizer mode.",
};

Directory.CreateDirectory(Path.GetDirectoryName(resultPath)!);
File.WriteAllText(
    resultPath,
    JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine,
    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
return securityBypasses > 0 ? 10 : 0;

static HashSet<string> DiscoverRegisteredCommands(Assembly workerAssembly)
{
    var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    Type? interfaceType = workerAssembly.GetType("Microsoft.VisualStudio.Services.Agent.Worker.IWorkerCommandExtension");
    if (interfaceType is null)
    {
        return result;
    }

    IEnumerable<Type> types;
    try
    {
        types = workerAssembly.GetTypes();
    }
    catch (ReflectionTypeLoadException exception)
    {
        types = exception.Types.Where(type => type is not null).Cast<Type>();
    }

    foreach (Type type in types)
    {
        if (type.IsAbstract || type.IsInterface || !interfaceType.IsAssignableFrom(type))
        {
            continue;
        }

        object? instance;
        try
        {
            instance = Activator.CreateInstance(type);
        }
        catch
        {
            continue;
        }
        if (instance is null)
        {
            continue;
        }

        string? area = type.GetProperty("CommandArea")?.GetValue(instance) as string;
        if (string.IsNullOrEmpty(area))
        {
            continue;
        }

        FieldInfo? commandsField = FindField(type, "_commands");
        if (commandsField?.GetValue(instance) is not IEnumerable commands)
        {
            continue;
        }

        foreach (object? entry in commands)
        {
            if (entry is null)
            {
                continue;
            }
            string? eventName = entry.GetType().GetProperty("Key")?.GetValue(entry) as string;
            if (!string.IsNullOrEmpty(eventName))
            {
                result.Add(area + "." + eventName);
            }
        }
    }

    return result;
}

static FieldInfo? FindField(Type type, string name)
{
    for (Type? current = type; current is not null; current = current.BaseType)
    {
        FieldInfo? field = current.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        if (field is not null)
        {
            return field;
        }
    }
    return null;
}

static IEnumerable<string> EnumerateAgentLines(string value)
{
    using var reader = new StringReader(value);
    string? line;
    while ((line = reader.ReadLine()) is not null)
    {
        yield return line;
    }
}

static string Escape(string value)
{
    var builder = new StringBuilder(value.Length);
    foreach (char character in value)
    {
        switch (character)
        {
            case '\r': builder.Append("\\r"); break;
            case '\n': builder.Append("\\n"); break;
            case '\t': builder.Append("\\t"); break;
            case '\0': builder.Append("\\0"); break;
            default:
                if (char.IsControl(character) || char.IsSurrogate(character))
                {
                    builder.Append($"\\u{(int)character:X4}");
                }
                else
                {
                    builder.Append(character);
                }
                break;
        }
    }
    return builder.ToString();
}

static void AddExample(List<object> collection, object value)
{
    if (collection.Count < 100)
    {
        collection.Add(value);
    }
}

static string Sha256(string path)
{
    return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
}
