using System.Globalization;
using System.Text.Json;

namespace EntraAudit;

public record Finding(string Sev, string Rule, string File, string Where, string Msg);

public static class Core
{
    public static int Rank(string sev) => sev switch { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };

    public static readonly string[] Privileged =
    {
        "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
        "User Administrator", "Exchange Administrator", "SharePoint Administrator", "Security Administrator",
        "Application Administrator", "Cloud Application Administrator", "Conditional Access Administrator",
        "Authentication Administrator", "Helpdesk Administrator"
    };

    static JsonElement? Prop(JsonElement el, string name)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        foreach (var p in el.EnumerateObject())
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) return p.Value;
        return null;
    }

    static string Str(JsonElement el, string name)
    {
        var v = Prop(el, name);
        return v is { ValueKind: JsonValueKind.String } ? v.Value.GetString()!.Trim() : "";
    }

    static bool? Bool(JsonElement el, string name)
    {
        var v = Prop(el, name);
        if (v is null) return null;
        return v.Value.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };
    }

    public static bool TryDate(string s, out DateTime d) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d);

    class User
    {
        public string Id = "", Name = "", Type = "";
        public bool Enabled = true;
        public bool? Mfa;
        public DateTime? LastSignIn;
    }

    static IEnumerable<JsonElement> Items(JsonElement root, string key)
    {
        if (root.ValueKind == JsonValueKind.Object)
        {
            var a = Prop(root, key) ?? Prop(root, "value");
            if (a is { ValueKind: JsonValueKind.Array }) return a.Value.EnumerateArray().ToList();
        }
        return Array.Empty<JsonElement>();
    }

    public static List<Finding> Audit(string text, string file, DateTime today)
    {
        var res = new List<Finding>();
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text); }
        catch (JsonException) { return Info(file, "not valid JSON, ignored"); }
        catch (ArgumentException) { return Info(file, "not valid JSON, ignored"); }
        using (doc)
        {
            var root = doc.RootElement;
            var users = new Dictionary<string, User>(StringComparer.OrdinalIgnoreCase);
            var order = new List<User>();
            foreach (var u in Items(root, "users"))
            {
                if (u.ValueKind != JsonValueKind.Object) continue;
                var usr = new User
                {
                    Id = Str(u, "id"),
                    Name = Str(u, "userPrincipalName") is { Length: > 0 } n ? n : Str(u, "displayName"),
                    Type = Str(u, "userType"),
                    Enabled = Bool(u, "accountEnabled") ?? true,
                    Mfa = Bool(u, "isMfaRegistered"),
                };
                var sia = Prop(u, "signInActivity");
                var last = sia is { } s ? Str(s, "lastSignInDateTime") : Str(u, "lastSignInDateTime");
                if (last != "" && TryDate(last, out var ld)) usr.LastSignIn = ld;
                if (usr.Name == "") usr.Name = usr.Id != "" ? usr.Id : "(unnamed)";
                if (usr.Id != "") users[usr.Id] = usr;
                order.Add(usr);
            }
            if (order.Count == 0) return Info(file, "no users found, ignored");

            var privByUser = new Dictionary<User, List<(string role, bool permanent)>>();
            int globalAdmins = 0;
            var seenGA = new HashSet<string>();
            foreach (var r in Items(root, "roleAssignments"))
            {
                if (r.ValueKind != JsonValueKind.Object) continue;
                var role = Str(r, "roleDefinitionName");
                if (role == "") role = Str(r, "roleName");
                var pid = Str(r, "principalId");
                var pname = Str(r, "principalName");
                User? usr = null;
                if (pid != "") users.TryGetValue(pid, out usr);
                if (usr is null && pname != "") usr = order.FirstOrDefault(x => string.Equals(x.Name, pname, StringComparison.OrdinalIgnoreCase));
                if (usr is null) continue;
                var kind = Str(r, "assignmentType");
                bool eligible = string.Equals(kind, "Eligible", StringComparison.OrdinalIgnoreCase);
                bool permanent = !eligible && Str(r, "endDateTime") == "";
                if (!privByUser.TryGetValue(usr, out var l)) privByUser[usr] = l = new();
                l.Add((role, permanent));
                if (role == "Global Administrator" && !eligible && seenGA.Add(usr.Name)) globalAdmins++;
            }

            foreach (var usr in order)
            {
                string where = file + "#" + usr.Name;
                bool guest = string.Equals(usr.Type, "Guest", StringComparison.OrdinalIgnoreCase);
                privByUser.TryGetValue(usr, out var roles);
                var privRoles = roles?.Where(x => Privileged.Contains(x.role, StringComparer.OrdinalIgnoreCase)).ToList() ?? new();
                if (!usr.Enabled)
                {
                    if (roles is { Count: > 0 })
                        res.Add(new("low", "ENT006", file, where, usr.Name + " is disabled but still holds " + string.Join(", ", roles.Select(x => x.role).Distinct())));
                    continue;
                }
                if (privRoles.Count > 0)
                {
                    var names = string.Join(", ", privRoles.Select(x => x.role).Distinct());
                    if (guest) res.Add(new("critical", "ENT003", file, where, usr.Name + " is a guest holding " + names));
                    if (usr.Mfa == false) res.Add(new("high", "ENT001", file, where, usr.Name + " holds " + names + " without MFA registered"));
                    foreach (var p in privRoles.Where(x => x.permanent).Select(x => x.role).Distinct())
                        res.Add(new("medium", "ENT002", file, where, usr.Name + " has a permanent active " + p + " assignment"));
                }
                else if (usr.Mfa == false && !guest)
                {
                    res.Add(new("medium", "ENT005", file, where, usr.Name + " has no MFA registered"));
                }
                if (usr.LastSignIn is { } ls && (today - ls).TotalDays > 90)
                    res.Add(new("medium", "ENT004", file, where, usr.Name + " has not signed in for " + (int)(today - ls).TotalDays + " days"));
            }
            if (globalAdmins > 5)
                res.Add(new("high", "ENT007", file, file, globalAdmins + " Global Administrators, keep it to five or fewer"));
        }
        return res;
    }

    static List<Finding> Info(string file, string msg) => new() { new("info", "ENT000", file, file, msg) };

    public static List<Finding> SortFindings(IEnumerable<Finding> f) =>
        f.OrderBy(x => Rank(x.Sev)).ThenBy(x => x.File, StringComparer.Ordinal).ThenBy(x => x.Rule, StringComparer.Ordinal).ThenBy(x => x.Where, StringComparer.Ordinal).ToList();

    static void Walk(string dir, string root, int depth, List<(string rel, string full)> acc)
    {
        if (depth > 30) return;
        try
        {
            foreach (var f in Directory.GetFiles(dir, "*.json").OrderBy(x => x, StringComparer.Ordinal))
                if ((new FileInfo(f).Attributes & FileAttributes.ReparsePoint) == 0)
                    acc.Add((Path.GetRelativePath(root, f).Replace('\\', '/'), f));
            foreach (var d in Directory.GetDirectories(dir).OrderBy(x => x, StringComparer.Ordinal))
                if (Path.GetFileName(d) != ".git" && (new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) == 0)
                    Walk(d, root, depth + 1, acc);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    public static List<Finding> AuditPath(string path, DateTime today, out int fileCount)
    {
        var files = new List<(string rel, string full)>();
        if (Directory.Exists(path)) Walk(path, path, 0, files);
        else files.Add((Path.GetFileName(path), path));
        fileCount = files.Count;
        var all = new List<Finding>();
        foreach (var (rel, full) in files)
        {
            string text = "";
            try { if (new FileInfo(full).Length <= 50_000_000L) text = File.ReadAllText(full); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            all.AddRange(Audit(text, rel, today));
        }
        return SortFindings(all);
    }
}
