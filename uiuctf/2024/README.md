Last weekend, I played [UIUCTF 2024](https://2024.uiuc.tf/) with [MEOW MEOW MEOW MEOW MEOW](https://ctftime.org/team/287661) and managed to solve both pwnypass challenges, which involved a buggy password manager extension. Chrome extensions and the mechanisms that underlie them are really neat, and it's pretty rare for them to appear in CTF challenges, so these problems were very refreshing! Below is a writeup of both parts -- the first required you to be able to leak the user's saved passwords on an arbitrary origin, and the second required you to be able to read a file at an arbitrary path on the user's filesystem.

## Overview

Upon visiting (almost) any page, the extension injects `content.js` which then checks if a login form exists on the page. If it does, then it communicates with `background.js` to fetch the user's credentials for the page's origin and displays them in an iframe (with location `autofill.html`, and in a more roundabout way -- see below). If the user logs in, then their login credentials are saved to storage.

Here's a quick demo:

[![flag1](https://img.youtube.com/vi/zxsY-koHeYw/0.jpg)](https://www.youtube.com/watch?v=zxsY-koHeYw)

At a slightly deeper level, the way the content script talks to the background script is with tokens -- the content script can send an 'issue token' request to the background script signalling intent for a specific purpose, and if that request is deemed valid by the background script, then it returns a token representing the request and some authentication code for the token which only it should be able to generate.

To actually perform the action, the content script can send a 'redeem token' request with the token and the authentication code, which the background script can verify against. This is all done over the `chrome.runtime` API, which page scripts have no access to (background scripts are more privileged than content scripts are more privileged than page scripts), so the control we have over making these requests is very limited.

As for the iframe, here's a snippet from `autofill.js`, which is loaded into `autofill.html`:

```js
// autofill.js

// snip

const params = new URLSearchParams(window.location.search);
const token = params.get("token");
const hmac = params.get("hmac");

async function main() {
    console.log("redeeming creds token...")
    const creds = await getCreds(token, hmac);
    console.log("got creds:")
    console.log(creds);

    let output = "";
    for (let cred of creds) {
        output += `
        <div class="entry">
        <div data-username="${cred.username}" class="user">${cred.username}</div>
        <div data-password="${cred.password}" class="pass">${cred.password}</div>
        </div><hr>`;
    }
    output = `<div>${output}</div>`;
    
    window.content.innerHTML = output;
}
main();

```

A few points:

1. The credentials themselves aren't actually passed to the iframe -- instead, after getting a read token and authentication code from the background script, *those* are passed to the iframe instead (via the search parameters), which then makes a 'redeem token' request to get the credentials. Subtly, this allows us to be able to make an arbitrary 'redeem token' request, but this will only be useful if we can get a valid code for our token (part 2).

2. The credentials are inserted directly into the page via `innerHTML` which means we potentially have arbitrary HTML injection if we can somehow save arbitrary credentials to storage! Sadly, this isn't quite uXSS, owing to the strict CSP of `script-src 'self' 'unsafe-eval'; object-src 'none';`.

Indeed, we *can* save arbitrary credentials to storage! Here's the content script:

```js
// content.js

// snip

async function init() {
    const passwordField = document.querySelector("input[type='password']");

    if (passwordField && passwordField.form) {
        const usernameField = passwordField.form.querySelector("input[type='text'], input[type='email']");
        if (usernameField) {
            // snip

            passwordField.addEventListener('change', async (event) => {
                if (usernameField.value && passwordField.value) {
                    [writeTok, writeHmac] = await issueToken('write', [usernameField.value, passwordField.value]);
                    console.log('issued new write token');
                }
            });
            usernameField.addEventListener('change', async (event) => {
                if (usernameField.value && passwordField.value) {
                    [writeTok, writeHmac] = await issueToken('write', [usernameField.value, passwordField.value]);
                    console.log('issued new write token');
                }
            })



            passwordField.form.addEventListener('submit', async (event) => {
                // redeem write token
                if (writeTok && writeHmac) {
                    console.log('redeeming write token...');
                    await redeemToken(writeTok, writeHmac);
                }
            });


            // snip
        }
    }
}

init();
```

Despite this script running on the same page as our page scripts, we couldn't e.g. overwrite `passwordField.addEventListener` with our own function which calls the listener immediately, since there are protections to stop page scripts from interfering with content scripts; in Chrome, [they execute in an entirely different JS context](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts).

> Firefox uses a separate mechanism, '[Xray Vision](https://firefox-source-docs.mozilla.org/dom/scriptSecurity/xray_vision.html)', which instead imposes a sort of integrity policy. You can see the listeners set by the content script if they're defined directly via the attribute instead of with `addEventListener`, but they'll be opaque and uncallable by page scripts.

However, events and the DOM are shared by both page scripts and content scripts, so we can set `usernameField.value` and `passwordField.value` to strings of our choosing, then use `passwordField.dispatchEvent(new Event('change'))` and `passwordField.form.dispatchEvent(new Event('change'))` to trigger the event listeners to write our credentials to storage!

## web/pwnypass

*495 points, 9 solves*

The user bot visits `https://pwnypass.c.hc.lc/login.php` and saves the credentials `sigpwny:<FLAG1>` to the manager before visiting our URL; our goal is to leak credentials from the featureless origin `https://pwnypass.c.hc.lc` (featureless, as in there's not really anything to exploit on that site).

Unfortunately, it's very hard to leverage our HTML injection. Though we can inject arbitrary HTML into a page with access to the same privileged APIs as `background.js`, we can't use these APIs since the only JS we can execute is from `'self'`, and none of these scripts seem to house any useful gadgets.

If we could get the flag on the same page as our HTML injection, then we could perform a CSS leak instead. Here's `background.js` with the irrelevant parts (for now) cut out:

```js
// background.js

// snip

const getOrigin = async (id) => new Promise((res)=>chrome.tabs.get(id, (t)=>setTimeout(()=>res(new URL(t.pendingUrl ?? t.url).origin),200)));

// snip

async function read(origin) {
    return await Promise.all((await getStorage("credentials"))
      .filter(c=>c.origin === origin)
      .map(async (c)=>(
        {
            ...c, 
            password: await dec(c["password"])
        }
      )
    ));
}

async function write(origin, username, password) {
    const credentials = await getStorage("credentials");
    credentials.push({
        origin,
        username,
        password: await enc(password)
    });
    await setStorage("credentials", credentials);
    return true;
}

async function evaluate(_origin, data) {
    return eval(data);
}


const commands = {
    read,
    write,
    evaluate // DEPRECATED! Will be removed in next release.
}

// snip

    if (request.action === "issue") {
        // generate token
        const ts = Math.floor(Date.now()/1000);
        const tab = sender.tab.id;
        const origin = await getOrigin(tab);
        console.log(tab);
        console.log(origin);
        const command = request.command;
        if (!commands.hasOwnProperty(command)) return;
        request.args.length = 2; // max 2 args
        if (request.args.some((arg) => arg.includes('|'))) return; // wtf, no.
        const args = request.args.join('|');
        console.log('issue successful!');

        const token = `${ts}|${tab}|${origin}|${command}|${args}`;
        return [token, await doHmac(token)];
    }
    if (request.action === "redeem") {
        // redeem a token
        const {token, hmac} = request;
        console.log(`redeeming ${token} ${hmac}`)
        if (await doHmac(token) !== hmac) return;

        let [ts, tab, origin, command] = token.split("|");
        if (parseInt(ts) + 60*5 < Math.floor(Date.now()/1000)) return;
        if (sender.tab.id !== parseInt(tab)) return;
        if ((p = await getOrigin(parseInt(tab))) !== origin) return;

        console.log('redemption successful!');

        const args = token.split("|").slice(-2);
        return await commands[command](origin, ...args);
    }

// snip
```

The essential thing is that the origin of the tab is embedded into the token, and only the credentials from the origin given in the token are retrieved (if the origin matches the tab's origin) so that all the tokens we generate from our malicious page are for our own origin, and not for `https://pwnypass.c.hc.lc`.

The way they get the origin of the tab is with `getOrigin`. Here's that code again:

```js
const getOrigin = async (id) => new Promise((res)=>chrome.tabs.get(id, (t)=>setTimeout(()=>res(new URL(t.pendingUrl ?? t.url).origin),200)));
```

This one-liner takes the origin from the `.pendingUrl` of the tab if it exists (otherwise just `.url`), which is, as described below by [developer.chrome.com](https://developer.chrome.com/docs/extensions/reference/api/tabs#:~:text=The%20URL%20the%20tab%20is%20navigating):

> The URL the tab is navigating to, before it has committed. This property is only present if the extension's manifest includes the "tabs" permission and there is a pending navigation.

Crucially, we can control this without destroying the event loop if we make a pending navigation, trigger the background logic, then cancel the navigation after `.pendingUrl` is read but before we are actually navigated\*\*\* -- this effectively means that we can spoof token requests from `https://pwnypass.c.hc.lc` if we can have the navigation stall for long enough!

There are a lot of ways to do this; the way I did it is with a massive file (maybe not very healthy for remote):

```html
<form id="bigform" enctype="multipart/form-data" action="https://pwnypass.c.hc.lc/login.php" method="POST">
  <input type=file id=fileinp name=lol>
</form>
<script>
let lmao = new DataTransfer();
lmao.items.add(new File(["a".repeat(59388419)], "lol"));
fileinp.files = lmao.files;

setTimeout(() => bigform.submit(), 10);

// logic after bigform is submitted and before window.stop() is invoked will have the spoofed origin of https://pwnypass.c.hc.lc

setTimeout(() => window.stop(), 700);
</script>
```

Some other ways were by exhausting the connection pool; if there are too many concurrent pending requests to the same destination, then any subsequent requests will be held pending until one of them finishes (this would also work even if the target site didn't exist); or with the same idea above but without the huge file, which was actually unnecessary -- you could just spam `window.stop`.

So, the plan as a whole is:

1. Spoof the current tab's origin to be `https://pwnypass.c.hc.lc` via `.pendingUrl`
2. Write malicious credentials to storage by dispatching events
3. Cause the credentials to be read from storage again by loading a new page
4. Spoof the origin again, so both our malicious credentials with the CSS injection and the flag are loaded
5. Leak the flag char-by-char by recursively importing a stylesheet which only generates once the current character is known

Please find my solver in the relevant dir -- it includes a server to generate the CSS, a setup page to write the credentials initially, and another page to trigger the read and start the leak.

Here's a demo of the exploit in action:

[![flag1](https://img.youtube.com/vi/kpuw9PABadE/0.jpg)](https://www.youtube.com/watch?v=kpuw9PABadE)

## web/pwnypass2

*498 points, 3 solves*

The second flag is in a directory with a randomly generated name on the user's filesystem. It's not loaded or read by `bot.js`. Our ability to leak credentials isn't useful here -- what we need is a way to escalate from page privileges to background script privileges.

In `background.js`, there's this:

```js
async function evaluate(_origin, data) {
    return eval(data);
}


const commands = {
    read,
    write,
    evaluate // DEPRECATED! Will be removed in next release.
}
```

If we can pass a token with the `evaluate` command then we'll be able to execute arbitrary JS with background script privileges. We're able to make arbitrary 'redeem token' requests (via `autofill.html`) but we need to be able to generate valid codes for our tokens as well. Here's how codes are generated:

```js
// background.js

// snip

let keyArr, key, iv;
const s2a = (text) => Uint8Array.from(Array.from(text).map(letter => letter.charCodeAt(0)));
const a2s = (arr) => Array.from(arr).map(v=>String.fromCharCode(v)).join('');
const concat = (a,b) => {
    const c = new Uint8Array(a.length+b.length);
    c.set(a,0);
    c.set(b,a.length);
    return c;
};
const fromHexString = (hexString) =>
    Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));  
const toHexString = (bytes) =>
    bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
  
const doHmac = async (d) => toHexString(new Uint8Array(await crypto.subtle.digest('SHA-256', concat(keyArr, s2a(d)))));

// snip
```

Authentication codes are generated using an HMAC of the token. The unpredictable, 32 byte key is prepended to the data, then this is all hashed using SHA256.

SHA256 is known to be vulnerable to hash length extension, where if some data is known to hash to something particular, then it can be predicted what that same data with any arbitrary data concatenated onto the end would hash to. HMACs usually prepend the data with the key and hash twice, once with the data and once with the result of the first hash, in order to protect against this; but here, since the data is at the end and hashing is only done once, we can concatenate directly onto the data and hash length extend!

To get a valid token/hash pair to length extend on, we need to leak the src of the iframe inserted by the content script (this is the only place we can get it from). The iframe is inserted into a closed shadow DOM -- how can we get a reference to it?

Again, there were many ways of doing it. The intended way was to use [performance APIs](https://developer.mozilla.org/en-US/docs/Web/API/Performance_API/Monitoring_bfcache_blocking_reasons). I used my old solution from a similar ASIS CTF challenge which used named window references, which are [known not to observe the shadow boundary](https://github.com/whatwg/html/issues/763).

Now that we're able to length extend, we need to correctly get the command to be read as `evaluate`. This is done by this logic:

```js
// background.js

// snip

    if (request.action === "redeem") {
        // redeem a token
        const {token, hmac} = request;
        console.log(`redeeming ${token} ${hmac}`)
        if (await doHmac(token) !== hmac) {
            return;
        }
        let [ts, tab, origin, command] = token.split("|");
        if (parseInt(ts) + 60*5 < Math.floor(Date.now()/1000)) return;
        if (sender.tab.id !== parseInt(tab)) return;
        if ((p = await getOrigin(parseInt(tab))) !== origin) {
            return;
        }
        console.log('redemption successful!');

        const args = token.split("|").slice(-2);
        return await commands[command](origin, ...args);
    }

// snip

```

The token is split on `|`, and the command is set to be the 4th item when split, but we can only extend; we can't modify what's already in the token. Thankfully, recall how the HMAC is calculated:

```js
// background.js

// snip

let keyArr, key, iv;
const s2a = (text) => Uint8Array.from(Array.from(text).map(letter => letter.charCodeAt(0)));
const a2s = (arr) => Array.from(arr).map(v=>String.fromCharCode(v)).join('');
const concat = (a,b) => {
    const c = new Uint8Array(a.length+b.length);
    c.set(a,0);
    c.set(b,a.length);
    return c;
};
const fromHexString = (hexString) =>
    Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));  
const toHexString = (bytes) =>
    bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
  
const doHmac = async (d) => toHexString(new Uint8Array(await crypto.subtle.digest('SHA-256', concat(keyArr, s2a(d)))));

// snip
```

The token is converted to a `Uint8Array` before being hashed -- since `Uint8Array`s store unsigned 8 bit integers, the maximum code point that can be stored is 255; anything higher is taken mod 256. This means that the `|` character is actually equivalent (in terms of calculating the hash) to many other characters, so we can replace all of the `|` symbols (which have code point `124`) in the original token with e.g. `ż` (which has code point `124 + 256`), so that we can force command to be read from our extended data instead!

> This doesn't break the `parseInt` since it ignores all the characters after the first `ż`.

Finally, with background script privileges, we have the `chrome.tabs` permission as specified in the manifest -- this means that we can successively open `file:///` URIs and use `chrome.tabs.executeScript` to get the page's HTML (which will be a directory listing) and send it back to us :)

This solver is also in its relevant dir. Here's a demo of the exploit in action:

[![flag2](https://img.youtube.com/vi/FCWvntLvK7E/0.jpg)](https://www.youtube.com/watch?v=FCWvntLvK7E)