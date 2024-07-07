# could not find a client-side hlextend lib and this was faster than impl

from flask import *
import hlextend
import base64
import time

app = Flask("lol", static_url_path="/", static_folder=".")

@app.route("/hlextend")
def lol():
	sha = hlextend.new("sha256")
	inp = sha.extend(request.args.get("inp").encode(), request.args.get("token").encode(), 32, request.args.get("hash"))
	h = sha.hexdigest()
	return [ base64.b64encode(inp).decode(), h ]


app.run("0.0.0.0", 5050)