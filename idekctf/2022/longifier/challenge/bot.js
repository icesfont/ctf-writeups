const puppeteer = require("puppeteer");

const visit = async (url) => {
	let finalURL = "";
	let content = "";
	let errorMsg = "";
	let browser;
	try {
		browser = await puppeteer.launch({
			headless: true,
			pipe: true,
			dumpio: true,
			IgnoreHTTPSErrors: true,
			executablePath: "/usr/bin/chromium-browser",
			args: [
				"--no-sandbox",
				"--disable-setuid-sandbox",
				"--js-flags=--noexpose_wasm,--jitless"
			]
		});

		let page = await browser.newPage();
		const client = await page.target().createCDPSession();
		await client.send("Page.setDownloadBehavior", {
			behavior: "allow",
			downloadPath: "/tmp"
		});

		await page.goto(url, { timeout: 10000 });
		await page.waitForTimeout(2500);
		finalURL = await page.url();
		content = await page.content();

	} catch(err) {
		errorMsg = `There was an error: ${err}`;
		console.log(err);
	} finally {
		if (browser) await browser.close();
		browser = null;
	}
	return {
		finalURL,
		content,
		errorMsg
	};
}

module.exports = { visit };
