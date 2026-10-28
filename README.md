# About Food

Πριν το deploy, κάνε push στο GitHub τις τελευταίες αλλαγές. Στο Render δημιούργησε Web Service και βάλε:

Build Command: go build -o app .
Start Command: ./app
Environment Variables:
APP_ENV = production
CSRF_SECRET = ένα σταθερό, τυχαίο μυστικό τουλάχιστον 32 χαρακτήρων

## Run locally

The application requires Go 1.25 or newer. From the repository root:

```powershell
$env:COOKIE_SECURE = "false"
go run .
```

Then open `http://localhost:8080`. The SQLite database is created at `data/aboutfood.db` by default; set `DATABASE_PATH` to use another location. Set `ADDR` to change the listening address.

The administrator page is not linked from the public site. Configure a private single-segment `ADMIN_PATH` with at least 24 random characters after the slash, plus `ADMIN_EMAIL` and an `ADMIN_PASSWORD` between 16 and 72 bytes. The private path is an extra privacy layer, not a substitute for the administrator credentials. Keep all three values private. Admin sessions and account-changing actions are checked by the server.

### Permanent Admin account

Run this setup once in PowerShell. Replace the email and password with your own values; the generated private path and credentials are saved for your Windows user and remain the same for future terminals and restarts:

```powershell
$adminPathBytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($adminPathBytes)
$adminPath = "/manage-" + [BitConverter]::ToString($adminPathBytes).Replace("-", "").ToLowerInvariant()
[Environment]::SetEnvironmentVariable("ADMIN_PATH", $adminPath, "User")
[Environment]::SetEnvironmentVariable("ADMIN_EMAIL", "your-admin-email@example.com", "User")
[Environment]::SetEnvironmentVariable("ADMIN_PASSWORD", "replace-with-a-private-password-of-at-least-16-characters", "User")
Write-Output ("http://localhost:8080" + $adminPath + "/login")
```

Open a new PowerShell terminal after setting these values. Start the server with `go run .` and use the printed URL to sign in.

### Prosorino admin account

Use this when you want the admin settings only for the current PowerShell window. Run these commands in the same terminal you use to start the server. A new random link is generated each time you repeat the setup:

```powershell
$adminPathBytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($adminPathBytes)
$env:ADMIN_PATH = "/manage-" + [BitConverter]::ToString($adminPathBytes).Replace("-", "").ToLowerInvariant()
$env:ADMIN_EMAIL = "your-admin-email@example.com"
$env:ADMIN_PASSWORD = "replace-with-a-private-password-of-at-least-16-characters"
$env:COOKIE_SECURE = "false"
Write-Output ("http://localhost:8080" + $env:ADMIN_PATH + "/login")
go run .
```

Close that PowerShell window to discard the temporary settings.

Set `CSRF_SECRET` to a stable, random value of at least 32 bytes before deploying. In production, set `APP_ENV=production` and serve the app behind HTTPS; startup refuses production settings without a CSRF secret and secure cookies. Generate a secret with PowerShell:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
```

## Deploy to Render

Create a Render Web Service from this repository and use:

- **Build Command:** `go build -o app .`
- **Start Command:** `./app`

The server reads Render's `PORT` environment variable automatically; locally it still defaults to port `8080`. Configure these environment variables in Render:

- `APP_ENV=production`
- `CSRF_SECRET` = a stable, randomly generated secret of at least 32 bytes

For temporary testing, no persistent disk is required. The default SQLite database supports registration and login, but its data may be erased when Render restarts or redeploys the service. Add `ADMIN_PATH`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` only if you also want to test the private admin page. Keep `CSRF_SECRET` stable while testing; changing it invalidates existing CSRF tokens. `COOKIE_SECURE` defaults to `true` when `APP_ENV=production`, so use the Render HTTPS URL.

## Supplier accounts

Supplier accounts are active immediately after registration and are signed in directly to the supplier dashboard. Existing supplier accounts that were waiting for approval are activated automatically the next time the server starts.

Both `/supplier/dashboard` and the dashboard template URL check the authenticated supplier role on the server. Do not expose the dashboard template through another static file server or bypass the Go handlers.

After login, buyers and suppliers return to the homepage, which displays a profile link and sign-out action instead of the login link. The profile link opens `/account`. Suppliers can manage their own listings at `/supplier/products`; product creation, editing, hiding, and deletion are scoped to the signed-in supplier. Active products are shown on the public Products page; hidden products remain in the supplier's account but are not published.

Buyers are sent to `/account` after signing in. The account page shows their stored account details and provides a CSRF-protected sign-out form. Supplier dashboard, profile, and product pages also provide sign-out.

Registration requires a unique email address and a password of at least 8 characters containing an uppercase letter and a symbol. Passwords are limited to 72 bytes for bcrypt compatibility.

## Administrator

The administrator account browser searches account names, business names, email addresses, and phone numbers. Blocking an account immediately invalidates its active sessions and hides its supplier products from the public marketplace; unblocking restores access. Deleting an account permanently removes its products and sessions as well.

## Checks

Run the backend tests with:

```powershell
go test ./...
```
