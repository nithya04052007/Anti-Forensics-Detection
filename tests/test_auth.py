"""
Automated unit & integration tests for User Registration, Authentication,
Session Management, and Protected Routes in Anti-Forensics Detection System.
"""

import unittest
import tempfile
import os
import json
from werkzeug.security import check_password_hash

from src.db.db_manager import DatabaseManager
from app import app, db as global_db


class TestAuthenticationSystem(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary database for test
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db = DatabaseManager(db_path=self.temp_db.name)

        # Configure Flask test client with the test DB
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key-dfir"
        self.client = app.test_client()

        # Monkeypatch app.db to use our isolated test database
        import app as app_module
        self.orig_db = app_module.db
        app_module.db = self.db

    def tearDown(self):
        # Restore original DB reference
        import app as app_module
        app_module.db = self.orig_db

        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except Exception:
                pass

    def test_default_admin_seeded(self):
        """Verify that default admin account is automatically seeded with hash."""
        user = self.db.get_user_by_username_or_email("admin")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin")
        self.assertEqual(user["role"], "admin")
        self.assertNotEqual(user["password_hash"], "admin123")
        self.assertTrue(user["password_hash"].startswith("pbkdf2:sha256"))
        self.assertTrue(check_password_hash(user["password_hash"], "admin123"))

    def test_register_page_renders(self):
        """Verify GET /register renders the sign up page."""
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create Account", response.data)
        self.assertIn(b"Full Name", response.data)
        self.assertIn(b"Email Address", response.data)
        self.assertIn(b"Confirm Password", response.data)

    def test_user_registration_success_and_permanent_storage(self):
        """Verify new user registration stores securely in database and logs in."""
        response = self.client.post("/register", data={
            "name": "Jane Investigator",
            "email": "jane@forensics.org",
            "password": "Password@123",
            "confirm_password": "Password@123"
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        # Verify permanent storage in SQLite database
        user = self.db.get_user_by_email("jane@forensics.org")
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "jane@forensics.org")
        self.assertEqual(user["full_name"], "Jane Investigator")
        self.assertNotEqual(user["password_hash"], "Password@123")
        self.assertTrue(check_password_hash(user["password_hash"], "Password@123"))

    def test_registration_password_mismatch(self):
        """Verify registration rejects mismatching passwords."""
        response = self.client.post("/register", data={
            "name": "Alex Smith",
            "email": "alex@forensics.org",
            "password": "Password@123",
            "confirm_password": "DifferentPassword@123"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Passwords do not match", response.data)
        self.assertIsNone(self.db.get_user_by_email("alex@forensics.org"))

    def test_registration_duplicate_email(self):
        """Verify registration rejects already registered email address."""
        # First registration
        self.db.create_user(
            username="investigator1",
            password="SecurePassword@1",
            email="duplicate@agency.gov",
            full_name="First User"
        )

        # Attempt to register again with same email
        response = self.client.post("/register", data={
            "name": "Second User",
            "email": "duplicate@agency.gov",
            "password": "Password@123",
            "confirm_password": "Password@123"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already exists", response.data)

    def test_login_page_renders_without_default_credentials(self):
        """Verify GET /login renders without visible default test credentials."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Email Address", response.data)
        self.assertIn(b"Create an account / Sign Up", response.data)
        # Verify default test credentials box is removed from page content
        self.assertNotIn(b"Default Admin Credentials", response.data)
        self.assertNotIn(b"admin123", response.data)

    def test_login_with_email_success(self):
        """Verify registered user can log in using email address and password."""
        self.db.create_user(
            username="analyst_bob",
            password="BobPassword@99",
            email="bob@cyberdfir.net",
            full_name="Bob Detective"
        )

        response = self.client.post("/login", data={
            "email": "bob@cyberdfir.net",
            "password": "BobPassword@99"
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        # Access dashboard as logged in user
        dash_response = self.client.get("/")
        self.assertEqual(dash_response.status_code, 200)
        self.assertIn(b"Bob Detective", dash_response.data)

    def test_login_unregistered_email_shows_error(self):
        """Verify logging in with non-existent email returns clear error message."""
        response = self.client.post("/login", data={
            "email": "unknown_email@nowhere.com",
            "password": "some_password"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No account found with this email address", response.data)

    def test_login_wrong_password_shows_error(self):
        """Verify logging in with registered email but incorrect password displays error."""
        self.db.create_user(
            username="alice",
            password="CorrectPassword@1",
            email="alice@cyberdfir.net",
            full_name="Alice Forensics"
        )

        response = self.client.post("/login", data={
            "email": "alice@cyberdfir.net",
            "password": "WrongPassword@2"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incorrect password", response.data)

    def test_unauthenticated_access_redirects_to_login(self):
        """Verify accessing / without session redirects to /login?next=%2F."""
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_unauthenticated_api_access_returns_401(self):
        """Verify accessing protected /api endpoints without session returns 401 JSON."""
        response = self.client.get("/api/scans")
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Authentication required", data["message"])

    def test_logout_clears_session(self):
        """Verify /logout clears session and blocks access to protected dashboard."""
        self.db.create_user(
            username="sam",
            password="SamPassword@1",
            email="sam@dfir.org",
            full_name="Sam Agent"
        )
        self.client.post("/login", data={"email": "sam@dfir.org", "password": "SamPassword@1"})

        # Log out
        logout_response = self.client.get("/logout", follow_redirects=False)
        self.assertEqual(logout_response.status_code, 302)
        self.assertEqual(logout_response.headers["Location"], "/login")

        # Verify access to / is redirected
        dash_response = self.client.get("/", follow_redirects=False)
        self.assertEqual(dash_response.status_code, 302)
        self.assertIn("/login", dash_response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
