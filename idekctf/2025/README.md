# web/midi visualizer

This challenge was written with @downgrade in the middle of the CTF as we were in urgent need of an easy web!!! The frontend demos were also a bit broken because I monkey-patched the site in Chrome DevTools overrides to make my MIDI exports from FL Studio work (which had `program=-1`, but needed to be `program=0`), but I forgot to copy it over to the remote dist. Oops...

The source is as follows:

```ts
import { serveDir } from "jsr:@std/http/file-server";

Deno.serve( {port: 1337}, async (req) => {
  const url = new URL(req.url);

  if (req.method === "POST" && url.pathname === "/upload") {
    try {
      const formData = await req.formData();
      const file = formData.get("file") as File;
      
      if (!file) {
        return new Response("no file provided", { status: 400 });
      }

      const bytes = new Uint8Array(await file.arrayBuffer());
      const randomBytes = crypto.getRandomValues(new Uint8Array(16));
      const hex = Array.from(randomBytes).map((b) =>
        b.toString(16).padStart(2, "0")
      ).join("");
      const filename = `${hex}.mid`;
      await Deno.writeFile(`uploads/${filename}`, bytes);
      
      return new Response(JSON.stringify({
        filename: filename,
      }), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (error) {
      return new Response(`upload failed`, { status: 500 });
    }
  }

  if (url.pathname === "/") {
    const file = await Deno.readFile("./index.html");
    return new Response(file, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (url.pathname.startsWith("/uploads/")) {
    return serveDir(req, {
      fsRoot: "uploads",
      urlRoot: "uploads",
    });
  }

  return serveDir(req, {
    fsRoot: "static",
    urlRoot: "static",
    showDirListing: true,
    showDotfiles: true,
  });
});

```

The goal is to read the flag in `uploads/`, but we don't know its filename. The file upload logic is unimportant as we have no control over the uploaded filename and having files with arbitrary content isn't very useful here. It would be great if we could read the directory listing of `uploads/` (which would tell us the flag's filename), but the intended handler's `showDirListing` is set to `false` [by default](https://github.com/denoland/std/blob/c3331d588f0e049fb464499161b8b8cd9977a508/http/file_server.ts#L706). Interestingly, the `static/` `serveDir` handler has it instead set to `true`. Could we use this other handler to read the directory listing of `uploads/` instead? How would we traverse out of `static/`?

Checking the [source code of the Deno file server](https://github.com/denoland/std/blob/c3331d588f0e049fb464499161b8b8cd9977a508/http/file_server.ts#L697), naive path traversal is handled by normalising the requested path before joining it with the provided `fsRoot`:

```ts
async function createServeDirResponse(
  req: Request,
  opts: ServeDirOptions,
) {
  const target = opts.fsRoot ?? ".";
  const urlRoot = opts.urlRoot;
  const showIndex = opts.showIndex ?? true;
  const cleanUrls = (opts as { cleanUrls?: boolean }).cleanUrls ?? false;
  const showDotfiles = opts.showDotfiles || false;
  const { etagAlgorithm = "SHA-256", showDirListing = false, quiet = false } =
    opts;

  const url = new URL(req.url);
  const decodedUrl = decodeURIComponent(url.pathname);
  let normalizedPath = posixNormalize(decodedUrl);

  if (urlRoot && !normalizedPath.startsWith("/" + urlRoot)) {
    return createStandardResponse(STATUS_CODE.NotFound);
  }

  // Redirect paths like `/foo////bar` and `/foo/bar/////` to normalized paths.
  if (normalizedPath !== decodedUrl) {
    url.pathname = normalizedPath;
    return Response.redirect(url, 301);
  }

  if (urlRoot) {
    normalizedPath = normalizedPath.replace(urlRoot, "");
  }

  // ...

  // Resolve path
  // If cleanUrls is enabled, automatically append ".html" if not present
  // and it does not shadow another existing file or directory
  let fsPath = join(target, normalizedPath);

  // ...
}
```

This should mean that any accessed files/directories are guaranteed to be children of the provided `fsRoot`, because `posixNormalize` guarantees that the returned path would either be relative (and fail the `.startsWith("/" + urlRoot)` check), or absolute (and not contain any `..` components). However, if a `urlRoot` is provided (as in the challenge), a simple string replacement is done to remove it from the path, *after this normalisation*. In particular, this could let us reintroduce a `..` component back into the `normalizedPath` if we provided a path like `/static../uploads` (which gets normalised back to `/../uploads`). Doing this lets us read the directory listing of `uploads/`, the flag's filename, and the flag :)

> Is this [nginx](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/)?

This is a simple misconfiguration, since our `urlRoot` should really have a slash on the end (i.e. `static/`). Or should it? The [official docs](https://docs.deno.com/examples/http_server_files/) and [comments in the source](https://github.com/denoland/std/blob/c3331d588f0e049fb464499161b8b8cd9977a508/http/file_server.ts#L637-L648) both don't have the slash on the end 🤔

# web/fnotes

This ended up being a very hard challenge! I was expecting 0-1 solves, and [FluxFingers](https://fluxfingers.net/) came very close to the solution, having found the payload for the dangling markup and knowing the intended idea for recovering the bot's session.

The concept for the challenge came from [WeChat Moments](https://en.wikipedia.org/wiki/Moments_(social_networking)), which is a social media platform that lets you share posts with mutual friends. The goal of the challenge was to make the bot add you as a friend (since the bot had a post containing the flag), and with no user interaction -- only the bot visiting your site.

Immediately, there's not much you *can* do! You can't CSRF a friend request since all routes (except `/login`) have CSRF protection, so you'd need to know the CSRF token, which you don't. It looks like you might be able to leak the CSRF token if you can get HTML injection on `notes.html`, but you'd need to get the bot to see your posts, and the bot can't see your posts because you're not their friend. Indeed, the only post they can see is their own flag post, which you can't control. The one thing you can do is to CSRF the bot to log in to your account instead -- this will become an issue later when you need to CSRF a friend request to yourself, since you're no longer logged in as the admin, but at least you can show the bot arbitrary posts now. (The CSRF token you leak would still be valid if you did somehow manage to recover the bot's session, since logging out doesn't remove the token from the session and [the token is reused if possible](https://github.com/pallets-eco/flask-wtf/blob/f7259e91dab7efac8b33c9f86cb86f16f90207a1/src/flask_wtf/csrf.py#L23-L63).)

## Leaking the CSRF token

HTML injection is probably stopped by this idk:

```py
# IN -> html5lib sanitize -> bleach linkify -> OUT
def safe_linkify(text):
	url_re = re.compile(r"https?://[^\s]+", re.IGNORECASE | re.VERBOSE | re.UNICODE)
	linker = Linker(url_re=url_re)
	return linker.linkify(
		html5lib.serialize(html5lib.parseFragment(text), sanitize=True)
	)
app.jinja_env.filters["safe_linkify"] = safe_linkify
```

We have linkifying occurring after sanitisation, a deprecated sanitiser, and a custom URL regex for some reason, so this is safe 😊

### Getting arbitrary well-formed HTML markup

Here, we can make use of the fact that the `html5lib` sanitiser [accepts the `<title>` tag in SVG](https://github.com/html5lib/html5lib-python/blob/fd4f032bc090d44fb11a84b352dad7cbee0a4745/html5lib/filters/sanitizer.py#L192), whereas `bleach` [accepts the `<title>` tag, but not the `<svg>` tag](https://github.com/mozilla/bleach/blob/d9aa7ef592d57dda56e26ba31d06e1b279c58eca/bleach/html5lib_shim.py#L84). When parsing foreign content such as SVG, [the `<title>` tag is not handled specially](https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign) (it *is* an HTML integration point but that's not important here), but when parsing HTML, [we switch to the RCDATA state](https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inhead).

This means that if we `safe_linkify` a payload such as `<svg><title><img name="</title>..."></title></svg>`, `html5lib`'s sanitiser will parse this, traverse the node tree, and remove nothing (`<svg> svg`, `<title> svg` and `<img name="..."> html` are all allowed), returning the HTML as-is -- but `bleach`'s linkifier will ignore the `<svg>` tag, treat the `<title>` tag as in the *HTML namespace*, and enter the RCDATA state! We can end this state prematurely with our own closing `</title>` in `<img name=`, and anything we provide in the `...` portion of the `name` attribute will now be parsed into arbitrary well-formed markup.

However, this still isn't enough to leak the CSRF token, owing to the strict CSP:

```py
@app.after_request
def add_security_headers(resp):
	resp.headers["X-Content-Type-Options"] = "nosniff"
	resp.headers["X-Frame-Options"] = "DENY"
	resp.headers["Content-Security-Policy"] = (
		"script-src 'none';"
		"style-src 'self';"
		"object-src 'none';"
		"frame-ancestors 'none';"
	)
	return resp
```

We don't have XSS and we can't do a CSS leak since we have `style-src 'self'` (and we can't write our own CSS payload in a note and include it as a stylesheet, since it would be as part of an HTML document and we have `X-Content-Type-Options: nosniff`). Arbitrary well-formed markup isn't enough: we need to be able to generate arbitrary dangling markup.

> I toyed around with the possibility of using history navigations to repopulate the CSRF token `<input>` into an attacker-controlled `<input>` and using a REDoS on `pattern=` to leak the token, similarly to [web/safestnote from DiceCTF 2025](https://adragos.ro/dice-ctf-2025-quals/#websafestnote) + [web/fire-leak from ASIS CTF Finals 2024](https://blog.arkark.dev/2024/12/30/asisctf-finals/#web-fire-leak), but from my limited testing this didn't seem to be possible and the CSRF token would have changed each guess anyway, since it was signed with the timestamp.

### Getting arbitrary dangling HTML markup

Our mutation above was possible because of a discrepancy that allowed us to have `html5lib` and `bleach` in two different tokenizer states when they should have been the same: `html5lib` in the [data state](https://html.spec.whatwg.org/multipage/parsing.html#data-state), and `bleach` in the [RCDATA state](https://html.spec.whatwg.org/multipage/parsing.html#rcdata-state). We should like to use this idea again here, but [`bleach` encodes `<>` in the RCDATA state](https://github.com/mozilla/bleach/blob/d9aa7ef592d57dda56e26ba31d06e1b279c58eca/bleach/html5lib_shim.py#L695) (this also covers RAWTEXT and script data, but I assume this naming is just historical), so we wouldn't be able to 'smuggle' our dangling HTML through character data in such states.

This is where the linkifier comes in. If you don't specify which tags not to traverse into when linkifying, `bleach`'s linkifier traverses them all -- even tags that force the tokenizer into a different state! This means you can get unencoded `<>` with a payload like `<style>http://<></style>` (which becomes `<style><a href="http://<>" rel="nofollow">http://&lt;&gt;</a></style>`). The problem is that our goal looks something like `<style><a href="http://</style>" rel="nofollow">http://&lt;/style&gt;</a></style>` (so that the `<style>` is closed by the `</style>` in the `href`), but there's no way to get the `</style>` in the `href` without closing the initial `<style>` that was passed into the linkifier. How can we get a closing tag as part of the character data of the tag if it closes the tag?

The intended solution was to use [this technique popularised by Gareth Heyes](https://x.com/garethheyes/status/1813658752245236105):

```html
<script>
<!--<script>
</script>
</script>
```

Pop quiz: which `</script>` closes the script tag? My syntax highlighter and the one in the tweet both seem to think it's the first one :)

Indeed and bizarrely, it's the *second* `</script>` which closes the script tag! This is completely spec-compliant, and [you can follow through the steps](https://html.spec.whatwg.org/multipage/parsing.html#script-data-state) if you want. For our purposes, this gives us the ability to have the closing tag (of a tag that switches the tokenizer to a non-data state and is not `<plaintext>`) inside the character data of the tag itself. Here's my payload, which then requires a little tweaking to make sure that the right attribute is dangled:

```html
<svg><title><img name="</title><script>http://<!--<script >http://</script><iframe/x'src='data:text/html,<iframe/src=%27...%27/name=%27 </script>"></title></svg>
```

Here's FluxFingers', which is much cleaner:

```html
<svg><title><div id="</title><script>https://a<!--<script><xss>b... <div id='</script><script>'>...</script>"> 
<div id="</script><iframe src='data:text/html;charset=utf16-le,...leak here..."></div>
csrftoken here
second note:
<div id="'></iframe>"></div></div>
```

Both solves use `data:` iframes to leak the CSRF token, from `window.name` and via UTF-16 encoding to bypass the dangling markup protection (which just checks for existence of `\n` and `<` in a URL) respectively!

> This challenge is actually nerfed, and originally had the additional CSP directive `default-src 'none';`! The intended solution to leak the CSRF token was a hopefully interesting-but-not-that-hard-to-find Chromium 0-day, bypassing this dangling markup protection, which you can try to search for if you'd like.

## Recovering the bot's session

Now that we have the CSRF token, we can send ourselves a friend request! Unfortunately, we had to log in as our own user at the start to do anything meaningful, so we'd just be sending friend requests from our own account. How do we log back in to the bot's account?

This challenge's way of communicating feedback is via [Flask flashes](https://flask.palletsprojects.com/en/stable/patterns/flashing/). Flashes are in turn implemented using Flask's sessions. Here's the source for `flash()` and `get_flashed_messages()`:

```py
def flash(message: str, category: str = "message") -> None:
    # ... long docstring omitted ...
    flashes = session.get("_flashes", [])
    flashes.append((category, message))
    session["_flashes"] = flashes
    app = current_app._get_current_object()  # type: ignore
    message_flashed.send(
        app,
        _async_wrapper=app.ensure_sync,
        message=message,
        category=category,
    )

def get_flashed_messages(
    with_categories: bool = False, category_filter: t.Iterable[str] = ()
) -> list[str] | list[tuple[str, str]]:
    # ... long docstring omitted ...
    flashes = request_ctx.flashes
    if flashes is None:
        flashes = session.pop("_flashes") if "_flashes" in session else []
        request_ctx.flashes = flashes
    if category_filter:
        flashes = list(filter(lambda f: f[0] in category_filter, flashes))
    if not with_categories:
        return [x[1] for x in flashes]
    return flashes
```

As opposed to other implementations (such as `express-session`), data associated with Flask sessions is stored in the cookie itself and signed to prevent tampering. When you modify a Flask session, the cookie has to be updated (via the `Set-Cookie` header) in the response to the client.

Here's where the key idea comes in: whenever the session is updated, in particular by `flash()` and `get_flashed_messages()` above, the response effectively *logs us back in again*, since the session cookie still reflects our logged-in user!

So, if we can set up a request which triggers a response that sets our session cookie again without logging us out (using flashes), *delay* this request somehow, perform the previous steps to leak the CSRF token, and *then* allow the first request to go through, we can effectively log ourselves back in to perform the CSRF :)

The intended way to do this was to block the connection pool and use a prerender request, since [these have `Lowest` priority](https://web.dev/articles/fetch-priority) and so the form submissions required for the above CSRF token leak would always take priority when a socket was freed, as they have `Highest` priority. Additionally, prerender requests count as top-level navigations, so they can send and set Lax cookies.

In order to have a GET request trigger a cookie-setting response (since prerender requests can only be GET requests), you would use the fact that every template builds on `base.html`, which calls `get_flashed_messages()` -- so you'd set up a flash message by CSRFing a POST request with a bad CSRF token to trigger the CSRF error handler (which flashes an error message), but cancelling the redirect so that your next GET request to e.g. `/notes/` calls `get_flashed_messages()`. (I cancelled the redirect by hitting the redirect limit.)

Here are the steps of the exploit in full:

1. Set up your next GET request to set the session cookie again in the response using the above;
2. Fill the connection pool;
3. Make a prerender request to `/notes/`;
4. CSRF the bot to log out, then log back in to your account, and go to `/notes/` to leak the CSRF token (for each request, unblock and reblock the connection pool to make sure the request can go through -- the prerender will never beat the reblocking request, since it has a lower priority);
5. Unblock the connection pool (so that the prerender request goes through and logs you back in);
6. CSRF a friend request to yourself!

You can find my solver attached [here](./fnotes/).

## Appendix

- I developed the challenge to be centered around this "re-login tech" idea from the very start. The `bleach`/`html5lib` concoction was added as another layer, and it ended up being way harder than I thought it'd be :)
- It should be possible to delay *any* request, not just prerenders! As explained in [this great article](https://blog.babelo.xyz/posts/css-exfiltration-under-default-src-self/), requests within priorities are not assigned sockets FIFO(!), but rather in an order according to port, then scheme, then host. This means that you could also block the connection pool with a bunch of *font requests* (`Highest` priority) to subdomains beginning with `aaa...` (on the same port and scheme), which would take priority over any requests you wished to hold back, and in particular a POST request. This would remove the need to cancel the redirect on the POST above, since you could just use the POST itself as the request to hold back. (I even played this challenge so I don't know how I missed this article.)
- You need a framework which closes the connection after each request, since otherwise the prerender request will prematurely reuse left-open connections. This is why the Flask dev server was used.
- I feared that people may try to lag the server instead in order to hold back the request, so I was considering making the challenge instanced with one sync worker, but I also feared that this may have led to too many deep rabbit holes (with people digging deep into the web framework source to find DoSes, which is also part of the reason why the URL regex was changed). The two main options I'd anticipated players would try to go for were either a server-side delay or a client-side delay as above, but what I hadn't considered was that you might have been able to send a huge request to maximise the latency between sending the request and receiving the response due to various network factors over the Internet (also perhaps due to processing time), which is what FluxFingers tried. I'm not sure if this ended up working in practice when targeting remote over the Internet, but if I had a bit more foresight to consider this as a possibility then I would've pointed the bot to the public address instead.

