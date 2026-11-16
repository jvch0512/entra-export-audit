.PHONY: build test sample

build:
	dotnet build src/EntraAudit.csproj -c Release -o build/out -v q --nologo $(RESTORE)

test: build
	dotnet run --project tests/Tests.csproj -c Release -v q --nologo $(RESTORE) && bash tests/cli.sh

sample: build
	mkdir -p docs site
	bin/entra-export-audit examples --today 2026-11-16 > docs/sample-output.txt; true
	bin/entra-export-audit examples --today 2026-11-16 --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "entra-export-audit" "Audits Microsoft Entra ID exports for admins without MFA, permanent privileged roles, guests with admin roles, stale accounts and too many Global Administrators. C#." "Synthetic data."
