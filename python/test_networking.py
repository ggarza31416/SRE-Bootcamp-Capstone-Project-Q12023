import unittest

from api import app


class TestConversionEndpoints(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    # test for valid input values

    def test_cidr_to_mask_success(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI"
        headers = {"Authorization": f"Bearer {token}"}
        response = self.app.get("/cidr-to-mask?value=1", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["output"], "128.0.0.0")

    def test_mask_to_cidr_success(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI"
        headers = {"Authorization": f"Bearer {token}"}
        response = self.app.get("/mask-to-cidr?value=128.0.0.0", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["output"], 1)

    # test for invalid input values

    def test_cidr_to_mask_fail(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.ABC"
        headers = {"Authorization": f"Bearer {token}"}
        response = self.app.get("/cidr-to-mask?value=1", headers=headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "You entered an invalid JWT token.")

    def test_mask_to_cidr_fail(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI"
        headers = {"Authorization": f"Bearer {token}"}
        response = self.app.get(
            "/mask-to-cidr?value=128.0.0.0.255.255.255", headers=headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["output"], "Invalid IP")


if __name__ == "__main__":
    unittest.main()
