# PKCE Demo

A minimal browser-based OAuth 2.0 PKCE flow against Google. Authenticates a user and displays the resulting ID token (JWT), access token, and refresh token.

## Prerequisites

- Go 1.21+
- A Google OAuth 2.0 client ID (Web application type)

## Google Console Setup

1. Go to [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials
2. Create or select an OAuth 2.0 Client ID of type **Web application**
3. Add `http://localhost:3000` to **Authorized redirect URIs**
4. Note the **Client ID** and **Client Secret**

## Running

```bash
cd test/pkce-demo
go run main.go
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

## Usage

1. Enter your Google Client ID (and Client Secret if using a Web application client)
2. Click **Sign in with Google**
3. Complete the Google auth flow
4. The page displays the decoded ID token claims, access token, and refresh token

## Output

The ID token is a standard Google OIDC JWT with claims including:

| Claim | Description |
|-------|-------------|
| `iss` | `https://accounts.google.com` |
| `sub` | Stable numeric user ID |
| `email` | User's email address |
| `azp` | OAuth client ID (authorized party) |
| `hd` | Hosted domain (G Suite/Workspace accounts only) |
| `exp` | Expiry (1 hour from issuance) |

## Signet

The ID token from this flow can be used with Signet's `/v1/auth` endpoint. The derived Signet `key_id` will be `iss:sub`, e.g.:

```
https://accounts.google.com:114810956681671373980
```

The `azp` value is what goes in `clientIds` when registering the issuer on-chain for a Signet group.
