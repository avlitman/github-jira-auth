from flask import Flask, request
import hashlib
import hmac
import os
app = Flask(__name__)

secret = os.environ['SECRET']
forward_to = os.environ['FORWARD_TO']

@app.route("/github-proxy-forwarder")
def github_proxy():
    signature_header = request.headers.get('X-Hub-Signature-256')
    hash_object = hmac.new(secret.encode('utf-8'), msg=body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if hmac.compare_digest(expected_signature, signature_header):
        res = requests.request(  # ref. https://stackoverflow.com/a/36601467/248616
            method          = request.method,
            url             = forward_to,
            headers         = {k:v for k,v in request.headers if k.lower() != 'host'}, # exclude 'host' header
            data            = request.get_data(),
            cookies         = request.cookies,
            allow_redirects = False,
        )
    
        #region exlcude some keys in :res response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']  #NOTE we here exclude all "hop-by-hop headers" defined by RFC 2616 section 13.5.1 ref. https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
        headers          = [
            (k,v) for k,v in res.raw.headers.items()
            if k.lower() not in excluded_headers
        ]
        #endregion exlcude some keys in :res response
    
        response = Response(res.content, res.status_code, headers)
        return response
        # send the web hook
    
if __name__ == "__main__":
    app.run()
