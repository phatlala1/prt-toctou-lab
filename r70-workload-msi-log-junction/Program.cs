internal static partial class Program
{
    private const uint DisableMaxPrivilege = 0x1;
    private const uint SeGroupUseForDenyOnly = 0x10;
    private const uint SeGroupIntegrity = 0x20;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const int TokenIntegrityLevel = 25;

    private static readonly JsonSerializerOptions s_json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("R70 requires Windows.");
            return 2;
        }

        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: orchestrate|parent|client ...");
            return 2;
        }

        try
        {
            return args[0] switch
            {
                "orchestrate" => await OrchestrateAsync(args),
                "parent" => await ParentAsync(args),
                "client" => await ClientAsync(args),
                _ => throw new ArgumentException($"Unknown mode: {args[0]}")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }
}
