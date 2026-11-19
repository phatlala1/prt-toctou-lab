#!/usr/bin/env bash
set -euo pipefail
mkdir -p evidence

dotnet --info | tee evidence/dotnet-info.txt
dotnet restore R73.csproj
dotnet build R73.csproj -c Release --no-restore

set +e
dotnet run --project R73.csproj -c Release --no-build -- default evidence/default.json
DEFAULT_RC=$?
dotnet run --project R73.csproj -c Release --no-build -- revalidate evidence/revalidate.json
REVALIDATE_RC=$?
python3 verify.py evidence/default.json evidence/revalidate.json
VERIFY_RC=$?
set -e

printf 'default_exit=%s\nrevalidate_exit=%s\nverify_exit=%s\n' "$DEFAULT_RC" "$REVALIDATE_RC" "$VERIFY_RC" | tee evidence/exit-codes.txt
find evidence -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > evidence/SHA256SUMS.txt
exit "$VERIFY_RC"
