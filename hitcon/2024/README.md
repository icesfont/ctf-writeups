# Private Browsing+ - web

To escape the data: iframe, we can use a similar idea to [spanote](https://blog.arkark.dev/2022/11/18/seccon-en/#Solution-6); if we load our site over the proxy (which renders the viewer page and does a further fetch to the same location to get the actual content of our site), navigate away, then call `history.back()`, we can load the cached fetch response instead. This abuses these ideas:

1. the history navigation checks the disk cache, and the fetch response is saved to disk cache;
2. both the fetch and the navigation are done to the same location, despite differing responses (and so we can make them have the same cache key).

In order to stop bfcache taking precedence over disk cache, which would just load our initial page again (bad), we can force bfcache invalidation by creating an opener-openee relation with the page we want the fetch response for. Hence, we have arbitrary control over the HTML on the page itself.

We can't XSS immediately due to the CSP:

```
default-src 'self'; style-src 'unsafe-inline' *; img-src *; font-src *; frame-src 'self' data:
```

and if we try and load a script from `'self'` via the proxy, then we trip this logic:

```js
// web/app.js

// block scripts just in case
if (
    res.headers['content-type'].toLowerCase().includes('script') ||
    req.headers['sec-fetch-dest'] === 'script'
) {
    res.headers['content-length'] = '0'
    delete res.headers['transfer-encoding']
}
```

which effectively kills the script. Actually, the script body is still sent after this -- it's just CL that's set to 0. Superficially, this doesn't make a difference since Chromium still only reads the number of bytes specified by the CL header, i.e. 0, but this means that our script body will be treated as a 2nd response which *the proxy doesn't interfere with*.

To make use of this, we need Chromium to send 2 script requests down the same connection (with keep-alive); the first to trigger this response splitting and the second to read the body of the first response as a whole response, i.e. request line, headers, and body.

Chromium requires some very specific conditions for this to happen. If you send a response to the first script where the `Content-Length` is less than the length of actual body, i.e. some of the body leaks into what should be the response to the 2nd request, then Chromium will close the connection at the point of sending the 2nd request.

Here's how the proxy request is done:

```js
// web/app.js

const proxyReq = http.request(reqObj, proxyRes => {
    if (responseHook) {
        responseHook(ctx, reqObj, proxyRes)
    }
    res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, proxyRes.headers)
    proxyRes.pipe(res)
    proxyRes.on('error', err => {
        console.error('proxyRes error', err)
    })
})
```

The dream scenario is:

1. send the 1st script request;
2. respond with just the headers of our 1st script response, at which point the callback will run and execute `res.writeHead`, which will write those headers to the client i.e. Chromium;
3. Chromium will interpret this as a complete response because of `Content-Length: 0`, so it'll reuse that connection when we send the 2nd script request;
4. don't respond when we receive the 2nd script request. Instead, send the *body* of the 1st script response, and that'll be sent to the client (because of `proxyRes.pipe(res)`) and interpreted as the entire 2nd script response!

One caveat is that `res.writeHead` doesn't actually flush the headers; they'll be flushed with the body when flush is called by `proxyRes.pipe(res)`. This means that we have to send at least 1 single byte of body to flush the headers. Because of the reason from earlier, this means that the connection won't be reused.

Thankfully, we can *force* `res.writeHead` to flush the headers! `res.writeHead` eventually calls `_storeHeader`, which calls [this](https://github.com/nodejs/node/blob/38b7ce3b1e54a8c20aa8892e2675f1ac95f2300b/lib/_http_outgoing.js#L587). `_storeHeader` is shared by both the http client *and* the http server implemented by Node; so this logic, which should be client-specific (since `Expect:` is a request header), applies to the server as well. Bizarrely, this means that we can provide `Expect: 100-continue` as a *response* header and that'll cause the headers to be flushed without any byte of the body being sent.

After this, we can use the same trick above to register a SW that replaces `/~note/` with our own page that sends the flag to our webhook.

Solve script in relevant dir -- run `app.js` and send admin to `/solve.html`.
