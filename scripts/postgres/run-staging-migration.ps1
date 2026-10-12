$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$node = 'C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
$source = Join-Path $projectRoot 'migration-backups\schema-probe-verified\data\aroused.sqlite'
$stagePointer = [IntPtr]::Zero
$testPointer = [IntPtr]::Zero
$stagePlain = $null
$testPlain = $null
$stageEscaped = $null
$testEscaped = $null

if (-not (Test-Path -LiteralPath $node)) { throw 'Bundled Node.js runtime was not found.' }
if (-not (Test-Path -LiteralPath $source)) { throw 'The documented, prepared SQLite migration source was not found.' }

try {
  $stageSecure = Read-Host 'Staging database password for aroused_staging_migrator' -AsSecureString
  $testSecure = Read-Host 'Test database password for aroused_test_migrator' -AsSecureString
  $stagePointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($stageSecure)
  $testPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($testSecure)
  $stagePlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($stagePointer)
  $testPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($testPointer)
  $stageEscaped = [uri]::EscapeDataString($stagePlain)
  $testEscaped = [uri]::EscapeDataString($testPlain)

  $env:AROUSED_STAGING_DATABASE_URL = "postgresql://aroused_staging_migrator:$stageEscaped@127.0.0.1:5432/aroused_staging"
  $env:AROUSED_STAGING_DATABASE_NAME = 'aroused_staging'
  $env:AROUSED_STAGING_DATABASE_ROLE = 'aroused_staging_migrator'
  $env:AROUSED_STAGING_DATABASE_DISPOSABLE = 'YES'
  $env:AROUSED_ALLOW_STAGING_POSTGRES_MIGRATION = 'YES'

  # Run the ordinary suite before the PostgreSQL test import, which intentionally
  # populates its disposable test database and does not clean it up.
  Remove-Item Env:AROUSED_TEST_POSTGRES_URL,Env:AROUSED_TEST_POSTGRES_DATABASE_NAME,Env:AROUSED_TEST_POSTGRES_DATABASE_ROLE -ErrorAction SilentlyContinue
  Push-Location $projectRoot
  try {
    Write-Host 'Running the complete existing local test suite (live PostgreSQL test is skipped here)...'
    & $node --test --test-reporter=spec '.\tests\*.test.mjs'
    if ($LASTEXITCODE -ne 0) { throw "Local test suite failed with exit code $LASTEXITCODE; staging import was not started." }

    $env:AROUSED_TEST_POSTGRES_URL = "postgresql://aroused_test_migrator:$testEscaped@127.0.0.1:5432/aroused_test"
    $env:AROUSED_TEST_POSTGRES_DATABASE_NAME = 'aroused_test'
    $env:AROUSED_TEST_POSTGRES_DATABASE_ROLE = 'aroused_test_migrator'
    Write-Host 'Running PostgreSQL integration tests against the separate disposable test database...'
    & $node --test --test-reporter=spec '.\tests\postgres-migration.test.mjs'
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL integration test failed with exit code $LASTEXITCODE; staging import was not started." }

    Write-Host 'Importing the documented prepared SQLite snapshot into the verified disposable staging database...'
    & $node '.\scripts\postgres\migrate-staging.mjs' $source
    if ($LASTEXITCODE -ne 0) { throw "Staging import failed with exit code $LASTEXITCODE." }
  } finally {
    Pop-Location
  }
} finally {
  Remove-Item Env:AROUSED_STAGING_DATABASE_URL,Env:AROUSED_TEST_POSTGRES_URL -ErrorAction SilentlyContinue
  Remove-Item Env:AROUSED_STAGING_DATABASE_NAME,Env:AROUSED_STAGING_DATABASE_ROLE,Env:AROUSED_STAGING_DATABASE_DISPOSABLE,Env:AROUSED_ALLOW_STAGING_POSTGRES_MIGRATION -ErrorAction SilentlyContinue
  Remove-Item Env:AROUSED_TEST_POSTGRES_DATABASE_NAME,Env:AROUSED_TEST_POSTGRES_DATABASE_ROLE -ErrorAction SilentlyContinue
  if ($stagePointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($stagePointer) }
  if ($testPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($testPointer) }
  $stageSecure = $null
  $testSecure = $null
  $stagePlain = $null
  $testPlain = $null
  $stageEscaped = $null
  $testEscaped = $null
}
