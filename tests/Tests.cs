using System.Text;
using EntraAudit;

int passed = 0, failed = 0;
void Check(bool ok, string name)
{
    if (ok) passed++;
    else { failed++; Console.WriteLine("FAIL: " + name); }
}
var today = new DateTime(2026, 11, 16, 0, 0, 0, DateTimeKind.Utc);
string Rules(string text) => string.Join(",", Core.Audit(text, "t.json", today).Select(f => f.Rule).OrderBy(x => x, StringComparer.Ordinal));
string U(string id, string extra = "") => "{\"id\":\"" + id + "\",\"userPrincipalName\":\"" + id + "@x.com\"" + (extra == "" ? "" : "," + extra) + "}";
string Doc(string users, string roles = "") => "{\"users\":[" + users + "],\"roleAssignments\":[" + roles + "]}";
string Role(string id, string role, string extra = "") => "{\"principalId\":\"" + id + "\",\"roleDefinitionName\":\"" + role + "\"" + (extra == "" ? "" : "," + extra) + "}";

// clean
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"))) == "", "clean user");
Check(Rules(Doc(U("a"))) == "", "unknown mfa not flagged");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("a", "Reports Reader"))) == "", "non privileged role");

// ENT001 + ENT002
Check(Rules(Doc(U("a", "\"isMfaRegistered\":false"), Role("a", "Global Administrator", "\"endDateTime\":\"2027-01-01T00:00:00Z\""))) == "ENT001", "admin without mfa");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("a", "Global Administrator"))) == "ENT002", "permanent active admin");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("a", "Global Administrator", "\"assignmentType\":\"Eligible\""))) == "", "eligible is fine");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("a", "Global Administrator", "\"assignmentType\":\"Active\",\"endDateTime\":\"2027-01-01T00:00:00Z\""))) == "", "time bound active is fine");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("a", "global administrator", "\"assignmentType\":\"Eligible\""))) == "", "role name case-insensitive");
foreach (var role in Core.Privileged)
    Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("a", role))) == "ENT002", "privileged role " + role);

// ENT003
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"userType\":\"Guest\""), Role("a", "User Administrator", "\"endDateTime\":\"2027-01-01T00:00:00Z\""))) == "ENT003", "guest admin");
Check(Core.Audit(Doc(U("a", "\"userType\":\"Guest\""), Role("a", "Security Administrator", "\"assignmentType\":\"Eligible\"")), "t", today)[0].Sev == "critical", "ENT003 is critical");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":false,\"userType\":\"Guest\""))) == "", "guest without mfa and no role not flagged");

// ENT004
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"signInActivity\":{\"lastSignInDateTime\":\"2026-08-17T00:00:00Z\"}"))) == "ENT004", "91 days is stale");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"signInActivity\":{\"lastSignInDateTime\":\"2026-08-18T00:00:00Z\"}"))) == "", "90 days not stale");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"signInActivity\":{\"lastSignInDateTime\":\"2026-08-15T00:00:00Z\"}"))) == "ENT004", "93 days stale");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"lastSignInDateTime\":\"2026-01-01T00:00:00Z\""))) == "ENT004", "flat lastSignInDateTime");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"signInActivity\":{\"lastSignInDateTime\":\"garbage\"}"))) == "", "bad date ignored");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true,\"accountEnabled\":false,\"signInActivity\":{\"lastSignInDateTime\":\"2020-01-01T00:00:00Z\"}"))) == "", "disabled stale not flagged");
Check(Core.Audit(Doc(U("a", "\"signInActivity\":{\"lastSignInDateTime\":\"2026-01-01T00:00:00Z\"}")), "t", today)[0].Msg.Contains("319 days"), "days in message");
Check(Core.Audit(Doc(U("a", "\"signInActivity\":{\"lastSignInDateTime\":\"2026-01-01T00:00:00Z\"}")), "t", new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc)).Count == 0, "today changes result");

// ENT005
Check(Rules(Doc(U("a", "\"isMfaRegistered\":false"))) == "ENT005", "member without mfa");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":false,\"accountEnabled\":false"))) == "", "disabled without mfa not flagged");

// ENT006
Check(Rules(Doc(U("a", "\"accountEnabled\":false,\"isMfaRegistered\":true"), Role("a", "Reports Reader"))) == "ENT006", "disabled with any role");
Check(Rules(Doc(U("a", "\"accountEnabled\":false"), Role("a", "Global Administrator"))) == "ENT006", "disabled admin only ENT006");

// ENT007
string Many(int n)
{
    var us = string.Join(",", Enumerable.Range(1, n).Select(i => U("g" + i, "\"isMfaRegistered\":true")));
    var rs = string.Join(",", Enumerable.Range(1, n).Select(i => Role("g" + i, "Global Administrator", "\"endDateTime\":\"2027-01-01T00:00:00Z\"")));
    return Doc(us, rs);
}
Check(Rules(Many(5)) == "", "five global admins ok");
Check(Rules(Many(6)) == "ENT007", "six global admins");
Check(Rules(Many(6).Replace("\"endDateTime\"", "\"x\"").Replace("{\"principalId\"", "{\"assignmentType\":\"Eligible\",\"principalId\"")) == "", "eligible globals not counted");

// shapes
Check(Rules("{\"value\":[" + U("a", "\"isMfaRegistered\":false") + "]}") == "ENT005", "value wrapper");
Check(Rules("{\"users\":[" + U("a", "\"isMfaRegistered\":true") + "],\"roleAssignments\":[{\"principalName\":\"A@X.COM\",\"roleName\":\"Global Administrator\"}]}") == "ENT002", "match by name, roleName alias");
Check(Rules("{\"users\":[{\"displayName\":\"Ana\",\"isMfaRegistered\":false}]}") == "ENT005", "displayName fallback");
Check(Core.Audit("{\"users\":[{\"isMfaRegistered\":false}]}", "t", today)[0].Where == "t#(unnamed)", "unnamed user");
Check(Rules(Doc(U("a", "\"isMfaRegistered\":true"), Role("zzz", "Global Administrator"))) == "", "assignment to unknown principal ignored");

// where
Check(Core.Audit(Doc(U("a", "\"isMfaRegistered\":false")), "f.json", today)[0].Where == "f.json#a@x.com", "where");

// ENT000
Check(Rules("") == "ENT000", "empty");
Check(Rules("{nope") == "ENT000", "invalid json");
Check(Rules("[]") == "ENT000", "array root");
Check(Rules("42") == "ENT000", "number root");
Check(Rules("null") == "ENT000", "null root");
Check(Rules("{\"users\":[]}") == "ENT000", "no users");
Check(Rules("{\"users\":\"x\"}") == "ENT000", "users wrong type");
Check(Core.Audit("", "e", today)[0].Sev == "info", "ENT000 is info");

// wrong types
Check(Rules("{\"users\":[1,null,\"a\",[],{\"accountEnabled\":\"no\",\"isMfaRegistered\":\"yes\",\"userType\":5}]}") == "", "wrong field types");
Check(Rules("{\"users\":[{\"id\":\"a\"}],\"roleAssignments\":[1,null,{\"principalId\":5}]}") == "", "wrong role types");

// sorting and rank
var list = new List<Finding> { new("low", "B", "a", "a", ""), new("high", "A", "z", "z", ""), new("high", "A", "a", "a", ""), new("critical", "Z", "z", "z", "") };
Check(string.Join(" ", Core.SortFindings(list).Select(f => f.Sev + f.File)) == "criticalz higha highz lowa", "sort order");
Check(Core.Rank("critical") < Core.Rank("high") && Core.Rank("low") < Core.Rank("info"), "rank");

// deep nesting
Check(Rules(new string('[', 5000) + new string(']', 5000)) == "ENT000", "deep nesting");

// fuzz
var rnd = new Random(7);
string[] bits = { "{", "}", "[", "]", ",", ":", "\"users\"", "\"roleAssignments\"", "\"id\"", "\"isMfaRegistered\"", "false", "true", "null", "1", "\"a\"", "\"roleDefinitionName\"", "\"Global Administrator\"", "\"signInActivity\"" };
bool crashed = false;
for (int i = 0; i < 3000; i++)
{
    var sb = new StringBuilder();
    for (int j = 0, n = rnd.Next(1, 40); j < n; j++) sb.Append(bits[rnd.Next(bits.Length)]);
    try { Core.Audit(sb.ToString(), "f.json", today); } catch (Exception) { crashed = true; }
}
var valid = Doc(U("a", "\"isMfaRegistered\":false"), Role("a", "Global Administrator"));
for (int i = 0; i <= valid.Length; i++)
    try { Core.Audit(valid.Substring(0, i), "f.json", today); } catch (Exception) { crashed = true; }
Check(!crashed, "random and truncated inputs do not throw");

Console.WriteLine($"{passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
