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