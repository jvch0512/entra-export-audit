using System.Text;
using EntraAudit;

static int Usage()
{
    Console.Error.WriteLine("usage: entra-export-audit PATH [--tsv] [--fail-on medium|high|critical] [--today YYYY-MM-DD]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.");
    return 2;
}

string? path = null, failOn = null;
bool tsv = false;
DateTime today = DateTime.UtcNow.Date;
for (int i = 0; i < args.Length; i++)
{
    var a = args[i];
    if (a == "--tsv") tsv = true;
    else if (a == "--fail-on")
    {
        if (++i >= args.Length || args[i] is not ("medium" or "high" or "critical")) return Usage();
        failOn = args[i];
    }
    else if (a == "--today")
    {
        if (++i >= args.Length || !DateTime.TryParseExact(args[i], "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out today)) return Usage();
    }
    else if (a.StartsWith('-')) return Usage();
    else if (path is not null) return Usage();
    else path = a;
}
if (path is null) return Usage();
if (!File.Exists(path) && !Directory.Exists(path))
{
    Console.Error.WriteLine("error: no such file or directory: " + path);
    return 2;
}
var p = path.Length > 1 ? path.TrimEnd('/') : path;
if (p == "") p = "/";
var fs = Core.AuditPath(p, today, out int n);
var head = $"{n} files, {fs.Count} findings";
var sb = new StringBuilder();
sb.Append(tsv ? "# " + head : head).Append('\n');
foreach (var f in fs)
{
    if (tsv) sb.Append(string.Join('\t', f.Sev, f.Rule, f.Where, f.Msg)).Append('\n');
    else
    {
        sb.Append(f.Sev.ToUpperInvariant().PadRight(8)).Append(' ').Append(f.Rule).Append(' ').Append(f.Where).Append('\n');
        sb.Append("         ").Append(f.Msg).Append('\n');
    }
}
Console.Out.Write(sb.ToString());
if (failOn is not null && fs.Any(f => Core.Rank(f.Sev) <= Core.Rank(failOn))) return 1;
return 0;
