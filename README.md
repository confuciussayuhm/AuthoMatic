# AuthoMatic

Automatic 401 Unauthorized handling for Burp Suite. AuthoMatic intercepts 401 responses, performs re-authentication, and retries requests with fresh tokens - seamlessly across all Burp tools.

## Features

- **Automatic Re-authentication**: Intercepts 401 responses and automatically logs in to get a fresh token
- **Works Everywhere**: Proxy, Repeater, Intruder, Scanner, and all other Burp tools
- **Smart Token Handling**: Extracts tokens from JSON bodies, cookies, or headers
- **Token Caching**: Caches tokens and only re-authenticates when needed
- **Easy Setup**: Right-click any login request → "Send to AuthoMatic"
- **Manual Injection**: Select text in Repeater → right-click → "Inject Token"
- **URL Pattern Matching**: Configure which URLs should use which credentials

## Installation

1. Download `authomatic-1.0.0.jar` from the [Releases](../../releases) page
2. In Burp Suite: **Extensions** → **Add** → Select the JAR file
3. The **AuthoMatic** tab will appear in Burp

## Quick Start

### 1. Capture a Login Request

Send a login request through Burp Proxy (or find one in HTTP History).

### 2. Send to AuthoMatic

Right-click the request → **Send to AuthoMatic**

### 3. Configure in the Import Dialog

- **URL Pattern**: Which URLs should use this config (e.g., `api.example.com/**`)
- **Credentials**: Enter username/password (replaces `${username}` and `${password}` placeholders)
- **Token Selection**: Click on the token value in the response preview to select it

### 4. Save and Enable

Click **Import** and ensure the configuration is enabled. AuthoMatic will now automatically handle 401s for matching URLs.

## How It Works

```
Request → 401 Response
            ↓
    AuthoMatic intercepts
            ↓
    Perform login request
            ↓
    Extract token from response
            ↓
    Retry original request with token
            ↓
    Return successful response
```

Your tools (Scanner, Intruder, etc.) never see the 401 - they receive the successful response directly.

## Configuration Options

### URL Patterns

| Pattern | Matches |
|---------|---------|
| `api.example.com/**` | Any path on api.example.com |
| `*.example.com/api/*` | Any subdomain, /api/ path |
| `example.com/v1/**` | Specific path prefix |

### Token Extraction

AuthoMatic can extract tokens from:
- **JSON Body**: Using JSON path (e.g., `data.access_token`, `token`)
- **Set-Cookie Headers**: Session cookies
- **Response Headers**: Custom token headers

### Token Injection

Tokens are injected into retry requests as:
- **Authorization: Bearer**: `Authorization: Bearer <token>`
- **Custom Header**: Any header name you specify
- **Cookie**: As a cookie value

### Credential Placeholders

In your login request body, use:
- `${username}` - Replaced with configured username
- `${password}` - Replaced with configured password

Example: `{"user": "${username}", "pass": "${password}"}`

## Manual Token Injection

For requests that need tokens but aren't getting 401s:

1. In Repeater, select the text where the token should go
2. Right-click → **Inject Token** → Select host
3. The selection is replaced with a fresh token

## Building from Source

```bash
git clone https://github.com/YOUR_USERNAME/AuthoMatic.git
cd AuthoMatic
mvn clean package
```

The JAR will be in `target/authomatic-1.0.0.jar`

## Requirements

- Burp Suite Professional or Community Edition
- Java 17 or higher

## License

MIT License - see [LICENSE](LICENSE) for details.
