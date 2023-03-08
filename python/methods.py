import os

import jwt
import mysql.connector
from flask import jsonify


class Token:
    def __init__(self):
        # initiating the db connection by using env variables.
        self.connection = mysql.connector.connect(
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            host=os.environ["DB_HOST"],
            port=os.environ["DB_PORT"],
            database=os.environ["DB_DATABASE"],
        )

    def generate_jwt(self, database_role):
        key = os.environ["JWT_KEY"]
        algorithm = "HS256"
        token = jwt.encode(database_role, key, algorithm=algorithm)
        return token

    def get_role(self, username, password):
        # using the sha2 function to derive the encrypted password in the DB
        query = """SELECT * FROM users WHERE username = %s
                AND password = SHA2(CONCAT(%s, salt), 512)"""
        values = (username, password)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, values)
                record = cursor.fetchone()
                if record:
                    database_role = record[3]
                    return {"role": database_role}, 200
                return {"error": "Invalid username or password."}, 403
        except self.connection.Error:
            # raising an exception if there is a server-side error
            return {"error": "Internal Server Error."}, 500

    def generate_token(self, username, password):
        response, status_code = self.get_role(username, password)
        if "error" in response:
            return response, status_code
        jwt_token = self.generate_jwt(response)
        return jsonify({"data": jwt_token}), status_code


class Restricted:
    def __init__(self):
        # initiating the db connection by using env variables
        self.key = os.environ["JWT_KEY"]
        self.authorized_roles = ["admin", "editor", "viewer"]

    def get_token(self, payload):
        # getting just the token value from the payload
        jwt_token = payload.replace("Bearer", "")[1:]
        return jwt_token

    def decode_token(self, payload):
        token_value = self.get_token(payload)
        try:
            decoded_token = jwt.decode(
                token_value,
                self.key,
                algorithms="HS256",
            )
            return decoded_token
        except Exception:
            return None

    def is_authorized(self, jwt_decoded_token):
        if jwt_decoded_token["role"] in self.authorized_roles:
            return True
        return False
