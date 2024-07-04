import requests
from flask import Flask, request, Response
import hashlib
import hmac
import os

app = Flask(__name__)

secret = os.environ['SECRET']
forward_to = os.environ['FORWARD_TO']


@app.route("/github-proxy-forwarder", methods=['POST'])
def github_proxy():
    signature_header = request.headers.get('X-Hub-Signature-256')
    body = request.get_data(as_text=True)
    hash_object = hmac.new(secret.encode('utf-8'), msg=body.encode('utf-8'), digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if hmac.compare_digest(expected_signature, signature_header):
        res = requests.request(
            method=request.method,
            url=forward_to,
            headers={k: v for k, v in request.headers if k.lower() != 'host'},  # exclude 'host' header
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
        )

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding',
                            'connection']
        headers = {
            k: v for k, v in res.raw.headers.items()
            if k.lower() not in excluded_headers
        }

        response = Response(res.content, res.status_code, headers)
        return response
        # TODO send the web hook


if __name__ == "__main__":
    app.run()
