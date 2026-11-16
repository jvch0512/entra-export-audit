# entra-export-audit

entra-export-audit reads a JSON export of Entra ID users and directory role assignments (Microsoft Graph shape, or a simple export with `users` and `roleAssignments`) and reports identity hygiene problems: privileged users without MFA, permanent active privileged assignments, guests holding admin roles, enabled accounts that have not signed in for 90 days, disabled accounts that still hold roles and more than five Global Administrators.

**Live demo:** https://jvch0512.github.io/entra-export-audit/ (Synthetic data.)

C# on .NET 8, no packages. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make build
bin/entra-export-audit examples
bin/entra-export-audit ./exports --tsv
bin/entra-export-audit ./exports --fail-on high       # exit 1 on any high finding
```

Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad input. Output is human text by default and TSV with `--tsv` (`# N files, M findings`, then `SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE`).

| Rule | Severity | What it catches |
|---|---|---|
| ENT001 | high | an enabled user with a privileged role and no MFA registered |
| ENT002 | medium | a permanent active (not eligible) privileged role assignment |
| ENT003 | critical | a guest user holding a privileged role |
| ENT004 | medium | an enabled account with no sign-in for 90 days (use --today) |
| ENT005 | medium | an enabled member account without MFA registered |
| ENT006 | low | a disabled account that still holds a role assignment |
| ENT007 | high | more than five Global Administrators |
| ENT000 | info | the file is not valid JSON or has no users |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It reads what is in the export. Conditional Access, PIM policies and group-based role assignments are not resolved.
- Privileged roles checked: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, User Administrator, Exchange Administrator, SharePoint Administrator, Security Administrator, Application Administrator, Cloud Application Administrator, Conditional Access Administrator, Authentication Administrator, Helpdesk Administrator.
- MFA is read from `isMfaRegistered`. If the field is absent the user is treated as unknown and not flagged.
- `--today YYYY-MM-DD` fixes the date used for the 90 day check, so results are reproducible.

## Where it fits

Identity and access reviews of Microsoft 365 and Azure tenants, and quick checks of exports before a customer call.

## Tests

```bash
make test    # A C# test program: every rule on good and bad exports, date handling, both input shapes, hostile JSON, fuzzing and CLI exit codes
```

MIT.
