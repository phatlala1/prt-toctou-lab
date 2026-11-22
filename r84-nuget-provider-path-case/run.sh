#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(pwd)"
LAB_DIR="$ROOT_DIR/lab"
PRODUCT_DIR="$ROOT_DIR/product"
EVIDENCE_DIR="$ROOT_DIR/evidence"
PROVIDER_DIR="$ROOT_DIR/provider"
TLS_DIR="$ROOT_DIR/tls"
PORT=5084

mkdir -p "$EVIDENCE_DIR" "$PROVIDER_DIR" "$TLS_DIR"

cat > "$ROOT_DIR/global.json" <<'EOF'
{
  "sdk": {
    "version": "10.0.404",
    "rollForward": "latestPatch",
    "allowPrerelease": false
  }
}
EOF

git -C "$LAB_DIR" rev-parse HEAD | tee "$EVIDENCE_DIR/lab-commit.txt"
git -C "$PRODUCT_DIR" rev-parse HEAD | tee "$EVIDENCE_DIR/azure-pipelines-tasks-commit.txt"
dotnet --version | tee "$EVIDENCE_DIR/dotnet-sdk-version.txt"
dotnet --info | tee "$EVIDENCE_DIR/dotnet-info.txt"
dotnet --list-runtimes | tee "$EVIDENCE_DIR/dotnet-runtimes.txt"
sha256sum \
  "$PRODUCT_DIR/Tasks/NuGetAuthenticateV1/main.ts" \
  "$PRODUCT_DIR/Tasks/NuGetAuthenticateV1/make.json" \
  "$PRODUCT_DIR/Tasks/NuGetAuthenticateV1/task.json" \
  | tee "$EVIDENCE_DIR/shipping-task-source-sha256.txt"

provider_url='https://github.com/microsoft/artifacts-credprovider/releases/download/v1.1.0/Microsoft.Net6.NuGet.CredentialProvider.zip'
curl --fail --show-error --silent --location "$provider_url" --output "$ROOT_DIR/provider-1.1.0.zip"
sha256sum "$ROOT_DIR/provider-1.1.0.zip" | tee "$EVIDENCE_DIR/provider-release-zip-sha256.txt"
unzip -q "$ROOT_DIR/provider-1.1.0.zip" -d "$PROVIDER_DIR"
provider_source_dll="$(find "$PROVIDER_DIR" -type f -name CredentialProvider.Microsoft.dll -print -quit)"
test -n "$provider_source_dll"
printf '%s\n' "$provider_source_dll" | tee "$EVIDENCE_DIR/provider-dll-path.txt"
sha256sum "$provider_source_dll" | tee "$EVIDENCE_DIR/provider-dll-sha256.txt"

plugin_parent="$HOME/.nuget/plugins/netcore"
plugin_dir="$plugin_parent/CredentialProvider.Microsoft"
mkdir -p "$plugin_parent"
rm -rf "$plugin_dir"
cp -R "$(dirname "$provider_source_dll")" "$plugin_dir"
provider_dll="$plugin_dir/CredentialProvider.Microsoft.dll"
test -f "$provider_dll"
printf '%s\n' "$provider_dll" > "$EVIDENCE_DIR/installed-provider-dll-path.txt"

openssl genrsa -out "$TLS_DIR/ca.key" 2048
openssl req -x509 -new -sha256 -days 1 \
  -key "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" \
  -subj '/CN=R84 Owned Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl genrsa -out "$TLS_DIR/server.key" 2048
openssl req -new -sha256 \
  -key "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" \
  -subj '/CN=r84.local'
cat > "$TLS_DIR/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:r84.local,DNS:alt.r84.local
EOF
openssl x509 -req -sha256 -days 1 \
  -in "$TLS_DIR/server.csr" \
  -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -out "$TLS_DIR/server.crt" -extfile "$TLS_DIR/server.ext"
sudo cp "$TLS_DIR/ca.crt" /usr/local/share/ca-certificates/r84-owned-ca.crt
sudo update-ca-certificates
echo '127.0.0.1 r84.local alt.r84.local' | sudo tee -a /etc/hosts
openssl x509 -in "$TLS_DIR/server.crt" -noout -subject -issuer -dates -ext subjectAltName \
  | tee "$EVIDENCE_DIR/server-certificate.txt"
sha256sum "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt" \
  | tee "$EVIDENCE_DIR/tls-certificate-sha256.txt"

export DOTNET_NOLOGO=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_ROLL_FORWARD=Major
export NUGET_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED=false
export NUGET_PLUGIN_PATHS="$provider_dll"
export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://r84.local:5084/TrustedFeed/v3/index.json","username":"R84_SYNTHETIC_USER","password":"R84_SYNTHETIC_SERVICE_CONNECTION_SECRET_7F92D0"}]}'
export NO_PROXY='r84.local,alt.r84.local,127.0.0.1,localhost'
export no_proxy="$NO_PROXY"

python3 "$LAB_DIR/r84-nuget-provider-path-case/server.py" \
  --port "$PORT" \
  --events "$EVIDENCE_DIR/server-events.jsonl" \
  --cert "$TLS_DIR/server.crt" \
  --key "$TLS_DIR/server.key" \
  > "$EVIDENCE_DIR/server-console.log" 2>&1 &
server_pid=$!
echo "$server_pid" > "$EVIDENCE_DIR/server.pid"
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error \
    --cacert "$TLS_DIR/ca.crt" \
    "https://r84.local:${PORT}/__health" \
    > "$EVIDENCE_DIR/health.json"; then
    ready=1
    break
  fi
  sleep 1
done
test "$ready" -eq 1

cli_trial() {
  local name="$1"
  local url="$2"
  set +e
  dotnet "$provider_dll" \
    -U "$url" -N -F Json -V Debug \
    > "$EVIDENCE_DIR/cli-${name}.stdout" \
    2> "$EVIDENCE_DIR/cli-${name}.stderr"
  local code=$?
  set -e
  printf '%s\n' "$code" > "$EVIDENCE_DIR/cli-${name}.exit"
}

cli_trial exact   "https://r84.local:${PORT}/TrustedFeed/v3/index.json"
cli_trial case    "https://r84.local:${PORT}/trustedfeed/v3/index.json"
cli_trial sibling "https://r84.local:${PORT}/TrustedFeedX/v3/index.json"
cli_trial host    "https://alt.r84.local:${PORT}/TrustedFeed/v3/index.json"

restore_trial() {
  local name="$1"
  local url="$2"
  local dir="$ROOT_DIR/work/${name}"
  mkdir -p "$dir"

  curl --fail --silent --show-error \
    --cacert "$TLS_DIR/ca.crt" \
    --request POST \
    "https://r84.local:${PORT}/__trial?name=${name}" \
    > "$EVIDENCE_DIR/trial-${name}.json"

  cat > "$dir/NuGet.Config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="r84" value="$url" protocolVersion="3" />
  </packageSources>
</configuration>
EOF

  cat > "$dir/R84.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RestoreDisableParallel>true</RestoreDisableParallel>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="R84.Synthetic.${name}" Version="1.0.0" />
  </ItemGroup>
</Project>
EOF

  set +e
  dotnet restore "$dir/R84.csproj" \
    --configfile "$dir/NuGet.Config" \
    --no-cache --force-evaluate --disable-parallel \
    --verbosity diagnostic \
    > "$EVIDENCE_DIR/restore-${name}.stdout" \
    2> "$EVIDENCE_DIR/restore-${name}.stderr"
  local code=$?
  set -e
  printf '%s\n' "$code" > "$EVIDENCE_DIR/restore-${name}.exit"
}

restore_trial exact   "https://r84.local:${PORT}/TrustedFeed/v3/index.json"
restore_trial case    "https://r84.local:${PORT}/trustedfeed/v3/index.json"
restore_trial sibling "https://r84.local:${PORT}/TrustedFeedX/v3/index.json"
restore_trial host    "https://alt.r84.local:${PORT}/TrustedFeed/v3/index.json"

set +e
python3 "$LAB_DIR/r84-nuget-provider-path-case/verify.py" "$EVIDENCE_DIR" \
  2>&1 | tee "$EVIDENCE_DIR/verifier-console.log"
verifier_code=${PIPESTATUS[0]}
set -e
printf '%s\n' "$verifier_code" > "$EVIDENCE_DIR/verifier-exit.txt"
exit "$verifier_code"
