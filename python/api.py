from convert import CidrMaskConvert, IpValidate
from flask import Flask, abort, jsonify, request
from methods import Restricted, Token

app = Flask(__name__)
login = Token()
protected = Restricted()
convert = CidrMaskConvert()
validate = IpValidate()


# Just a health check
@app.route("/")
def urlRoot():
    return "OK"


# Just a health check
@app.route("/_health")
def urlHealth():
    return "OK"


# e.g. http://127.0.0.1:8000/login
@app.route("/login", methods=["POST"])
def url_login():
    user_name = request.form.get("username")
    password = request.form.get("password")
    if user_name is None or password is None:
        return jsonify({"error": "Username and password are required."}), 400
    jwt_token = login.generate_token(user_name, password)
    return jwt_token


# e.g. http://127.0.0.1:8000/cidr-to-mask?value=8
@app.route("/cidr-to-mask")
def urlCidrToMask():
    var1 = request.headers.get("Authorization")
    if not protected.access_Data(var1):
        abort(401)
    val = request.args.get("value")
    r = {
        "function": "cidrToMask",
        "input": val,
        "output": convert.cidr_to_mask(val),
    }
    return jsonify(r)


# # e.g. http://127.0.0.1:8000/mask-to-cidr?value=255.0.0.0
@app.route("/mask-to-cidr")
def urlMaskToCidr():
    var1 = request.headers.get("Authorization")
    if not protected.access_Data(var1):
        abort(401)
    val = request.args.get("value")
    r = {
        "function": "maskToCidr",
        "input": val,
        "output": convert.mask_to_cidr(val),
    }
    return jsonify(r)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
