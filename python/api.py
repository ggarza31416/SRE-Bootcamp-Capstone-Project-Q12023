from convert import CidrMaskConvert, IpValidate
from flask import Flask, jsonify, request
from methods import Restricted, Token

app = Flask(__name__)
login = Token()
protected = Restricted()
convert = CidrMaskConvert()
validate = IpValidate()


def handle_request(request_header, request_value, conversion_function):
    if not request_header or not request_value:
        return jsonify({"error":
                        "Authorization Header and Value are required."}), 400
    decoded_token = protected.decode_token(request_header)
    if decoded_token is None:
        return jsonify({"error": "You entered an invalid JWT token."}), 400
    is_authorized = protected.is_authorized(decoded_token)
    if is_authorized:
        response = {
            "function": conversion_function.__name__,
            "input": request_value,
            "output": conversion_function(request_value),
        }
        return jsonify(response)
    return jsonify({"error":
                    "You Role is not authorized to perform this action"}), 401


# Just a health check
@app.route("/")
def url_root():
    return "OK"


# Just a health check
@app.route("/_health")
def url_health():
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


@app.route("/cidr-to-mask")
def url_cidr_to_mask():
    request_header = request.headers.get("Authorization")
    request_value = request.args.get("value")
    return handle_request(request_header, request_value, convert.cidr_to_mask)


@app.route("/mask-to-cidr")
def url_mask_to_cidr():
    request_header = request.headers.get("Authorization")
    request_value = request.args.get("value")
    return handle_request(request_header, request_value, convert.mask_to_cidr)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
