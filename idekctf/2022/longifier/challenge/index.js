const { visit } = require("./bot.js");
const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;
let flag;
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

app.use((req, res, next) => {
	return next();
})

app.get("/", (req, res, next) => res.render("index", { errorMsg: "" }));
app.post("/", async (req, res, next) => {
	const { url } = req.body;
	let { finalURL, content, errorMsg } = await visit(url);
	content = content.replace(flag, "[REDACTED]");
	if (errorMsg) return res.render("index", { errorMsg });
	return res.render("visited", { finalURL, url, content });
});

app.listen(PORT, () => {
	console.log(`Listening on port ${PORT}`);
	flag = "idek{fake_flag}";
	console.log("Flag initialised");
});
