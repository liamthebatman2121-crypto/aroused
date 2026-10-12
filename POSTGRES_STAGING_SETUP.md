# PostgreSQL staging setup (Windows)

## Current environment check

PostgreSQL 18.6 and its command-line tools are installed under `C:\Program Files\PostgreSQL\18\bin`. The local server responds on `127.0.0.1:5432`. Windows denies service-manager inspection, but the user authenticated in `psql`. The `aroused_staging` database and `aroused_staging_migrator` login were created and verified: the database owner matches the login, the marker is correct, and login is enabled. A separate `aroused_test` database and `aroused_test_migrator` login were also created and marked; importer preflight will verify that test target before writing. The original `.env` remains untouched. A prepared source integrity check passed, and its 16 existing tables match the current SQLite database across all common columns. The `pg` Node dependency is installed; `npm install` generated `package-lock.json` because none existed. No staging/test connection variables are present in the current process. An existing `.env` file is present and was not read or changed. The importer requires an explicit DSN, exact database name, dedicated database-owner role, disposable confirmation, and marker comment; it refuses databases with public-schema objects or additional user schemas.

## Option A: install a local staging server

1. Open the [PostgreSQL Windows installers page](https://www.postgresql.org/download/windows/). It links to the EDB interactive installer and describes the bundled server, pgAdmin, and StackBuilder. Choose a stable Windows-compatible installer; install PostgreSQL Server, Command Line Tools, and optionally pgAdmin. Keep port `5432`. Set a strong password for the `postgres` administrator and store it in a password manager. The official PostgreSQL download page notes that its Windows installer is hosted by EDB.
2. Open PowerShell and confirm the service and client exist. Adjust the version folder if the installer selected a different major version:

   ```powershell
   Get-Service *postgres*
   & "$env:ProgramFiles\PostgreSQL\18\bin\psql.exe" --version
   ```

3. Create a dedicated staging login and a new, isolated database. This uses `psql`'s hidden password prompt; do not put the admin password in a command or script:

   ```powershell
   & "$env:ProgramFiles\PostgreSQL\18\bin\psql.exe" -W -h 127.0.0.1 -p 5432 -U postgres -d postgres
   ```

   At the `postgres=#` prompt, enter:

   ```sql
   CREATE ROLE aroused_staging_migrator LOGIN;
   ```

   Then set that role's password without echoing it:

   ```text
   \password aroused_staging_migrator
   ```

   Enter and confirm a unique staging password at the prompts. Then create and mark the new database:

   ```sql
   CREATE DATABASE aroused_staging OWNER aroused_staging_migrator;
   COMMENT ON DATABASE aroused_staging IS 'aroused-disposable-staging';
   ```

   Exit with `\q`. The database comment is an explicit safety marker checked by the importer before it opens a write transaction.
4. In the project `outputs` directory, install the declared PostgreSQL client dependency:

   ```powershell
   npm install
   ```

   Use Node.js `22.13+` for the app and tests. This workspace's bundled Node 24 executable is `C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe`.
5. Configure the connection only in the current PowerShell process. The password prompt is hidden and the password is URI-escaped in memory; the command does not display it or write it to `.env`:

   ```powershell
   $securePassword = Read-Host 'Staging database password' -AsSecureString
   $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
   try {
     $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
     $escapedPassword = [uri]::EscapeDataString($plainPassword)
     $env:AROUSED_STAGING_DATABASE_URL = "postgresql://aroused_staging_migrator:$escapedPassword@127.0.0.1:5432/aroused_staging"
   } finally {
     if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
     $plainPassword = $null
     $escapedPassword = $null
   }
   $env:AROUSED_STAGING_DATABASE_NAME = 'aroused_staging'
   $env:AROUSED_STAGING_DATABASE_ROLE = 'aroused_staging_migrator'
   $env:AROUSED_STAGING_DATABASE_DISPOSABLE = 'YES'
   $env:AROUSED_ALLOW_STAGING_POSTGRES_MIGRATION = 'YES'
   ```

6. Only after the local server is available and the database has been explicitly created and marked, run the migration against a prepared 31-table SQLite copy:

   ```powershell
   & 'C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' `
     .\scripts\postgres\migrate-staging.mjs `
     .\migration-backups\schema-probe-verified\data\aroused.sqlite
   ```

   The importer reports per-table counts and relationship counts. It does not change `server.mjs` runtime configuration or the SQLite source. It requires an empty, marked database. Do not reuse that populated staging database for a second run; create and mark a new disposable database instead.

## Option B: connect to an existing staging PostgreSQL database

Ask the database owner to provide a dedicated, disposable database (not a production database), the hostname, port, database name, TLS requirements, and a least-privilege login that owns the new empty database. Configure `AROUSED_STAGING_DATABASE_ROLE` to that dedicated database owner/login. Have the owner mark the database:

```sql
COMMENT ON DATABASE aroused_staging IS 'aroused-disposable-staging';
```

It must have a name ending in `_staging` or `_test`, no user-created schemas, and no objects in `public`. Ensure your network can reach the server. Set the same environment variables as step 5 with that host and database name. For TLS, include the connection parameters supplied by the provider in the URL (for example `sslmode=require`); never disable TLS for a remote database.

## PostgreSQL integration test

Use a second disposable, empty, marked database named `aroused_test`. Create its dedicated login/database from the `postgres` administrator connection using:

```sql
CREATE ROLE aroused_test_migrator LOGIN;
```

Then use `\password aroused_test_migrator` at the `psql` prompt to set its password, followed by:

```sql
CREATE DATABASE aroused_test OWNER aroused_test_migrator;
COMMENT ON DATABASE aroused_test IS 'aroused-disposable-staging';
```

Set its URL with a hidden password prompt; the password is never displayed or written to a file:

```powershell
$secureTestPassword = Read-Host 'Test database password' -AsSecureString
$testPasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureTestPassword)
try {
  $plainTestPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($testPasswordPointer)
  $escapedTestPassword = [uri]::EscapeDataString($plainTestPassword)
  $env:AROUSED_TEST_POSTGRES_URL = "postgresql://aroused_test_migrator:$escapedTestPassword@127.0.0.1:5432/aroused_test"
} finally {
  if ($testPasswordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($testPasswordPointer) }
  $plainTestPassword = $null
  $escapedTestPassword = $null
}
$env:AROUSED_TEST_POSTGRES_DATABASE_NAME = 'aroused_test'
$env:AROUSED_TEST_POSTGRES_DATABASE_ROLE = 'aroused_test_migrator'
```

Do not copy the staging URL, because it names a different database. Set the staging guard variables (disposable and migration confirmation) as shown in step 5 if they are not already set. The test migrates a temporary SQLite fixture containing a user, owned album, media, and quarantined pipeline row, then verifies IDs, owner, album/media links, status, all table counts, unique/FK constraints, and relationship counts. It populates the test database and does not clean it up; use a fresh disposable database each run. With the test DSN configured, run the commands below.

Then run:

```powershell
& 'C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' --test --test-reporter=spec .\tests\postgres-migration.test.mjs
& 'C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' --test --test-reporter=spec .\tests\*.test.mjs
```

To clear connection variables from the current shell afterward without printing them:

```powershell
Remove-Item Env:AROUSED_STAGING_DATABASE_URL,Env:AROUSED_TEST_POSTGRES_URL -ErrorAction SilentlyContinue
Remove-Item Env:AROUSED_STAGING_DATABASE_NAME,Env:AROUSED_STAGING_DATABASE_DISPOSABLE,Env:AROUSED_ALLOW_STAGING_POSTGRES_MIGRATION,Env:AROUSED_TEST_POSTGRES_DATABASE_NAME -ErrorAction SilentlyContinue
Remove-Item Env:AROUSED_STAGING_DATABASE_ROLE,Env:AROUSED_TEST_POSTGRES_DATABASE_ROLE -ErrorAction SilentlyContinue
```

This migration phase does not switch the application off SQLite and does not copy or delete media.

## One-command migration runner

After creating and marking both disposable databases above, exit psql with \q, change PowerShell to the project outputs folder, then run:

```powershell
.\scripts\postgres\run-staging-migration.ps1
```

The runner requests each role password through hidden prompts, runs the ordinary suite with the live PostgreSQL test disabled, runs the PostgreSQL integration test once against the separate disposable test database, then runs the staging import. It clears connection variables and password buffers when it exits. The live test database is populated and intentionally not cleaned up; use a new marked disposable test database for another run.

## Latest run status (2026-10-09)

The full local suite passed 9/9 with the PostgreSQL test skipped; the PostgreSQL-specific suite passed 3/3. The staging import completed successfully: 31 table counts, 7 relationship counts, 22 unique indexes, and 42 foreign keys verified. aroused_test has been populated by the integration test and requires a fresh marked disposable database before another run. The application remains on SQLite. See PRODUCTION_READINESS.md for the final status.
