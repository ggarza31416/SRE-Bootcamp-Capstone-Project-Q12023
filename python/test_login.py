import unittest

from api import app


class TestLoginEndpoint(unittest.TestCase):
    def setUpClass(self):
        self.client = app.test_client()

    # test for valid input values
    def test_login_success(self):
        expected_result = {
            "data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI"
        }
        with self.client:
            response = self.client.post(
                "/login", data={"username": "admin", "password": "secret"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, expected_result)

    def test_login_fail(self):
        expected_result = {"error": "Invalid username or password."}
        with self.client:
            response = self.client.post(
                "/login", data={"username": "admin", "password": "wrong_password"}
            )
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json, expected_result)


if __name__ == "__main__":
    unittest.main()
