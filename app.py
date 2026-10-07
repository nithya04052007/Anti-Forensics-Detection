"""
Automated Anti-Forensics Detection System — Web Dashboard & API (Phase 2)
Provides interactive user-driven evidence file selection via Windows File Explorer,
real-time TeamMember1 forensic scanning, ML Random Forest risk assessment,
permanent SQLite storage, historical scan viewer, and PDF report generation.
"""

import os
import sys
import json
from functools import wraps
from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for, flash

from src.db.db_manager import DatabaseManager
from src.analysis.file_scanner import run_single_file_scan, DEFAULT_DB_PATH, REPORTS_DIR
from main import run_pipeline
from src.collection.file_collector import FileCollector
from src.collection.event_log_collector import EventLogCollector
from src.collection.registry_collector import RegistryCollector
from src.utils.simulator import ForensicSandboxSimulator
from src.utils.pdf_generator import generate_forensic_pdf_report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or "anti-forensics-dfir-secure-key-2026"

db = DatabaseManager(db_path=DEFAULT_DB_PATH)


@app.after_request
def add_security_headers(response):
    """Enforce strict no-cache headers for authenticated API endpoints to prevent local data leakage."""
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def login_required(f):
    """
    Decorator to protect routes from unauthenticated access.
    Redirects browser requests to /login and returns 401 for API requests.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"status": "error", "message": "Authentication required. Please log in."}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# ============================================================================
# Authentication Routes (Register, Login, Logout)
# ============================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """Render sign up page and register new user account."""
    if "user_id" in session:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        if request.is_json:
            data = request.get_json() or {}
            full_name = data.get("name", "").strip()
            email = data.get("email", "").strip().lower()
            password = data.get("password", "")
            confirm_password = data.get("confirm_password", "")
        else:
            full_name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

        # Input Validations
        if not full_name:
            error = "Please enter your full name."
        elif not email or "@" not in email or "." not in email:
            error = "Please enter a valid email address."
        elif not password or len(password) < 6:
            error = "Password must be at least 6 characters long."
        elif password != confirm_password:
            error = "Passwords do not match. Please verify and re-enter."
        else:
            # Check if email is already registered
            existing_user = db.get_user_by_username_or_email(email)
            if existing_user:
                error = "An account with this email address already exists. Please log in."
            else:
                # Generate unique username from email
                base_username = email.split("@")[0].replace(".", "_").replace("-", "_")
                candidate_username = base_username
                suffix = 1
                while db.get_user_by_username_or_email(candidate_username):
                    candidate_username = f"{base_username}_{suffix}"
                    suffix += 1

                user_id = db.create_user(
                    username=candidate_username,
                    password=password,
                    email=email,
                    full_name=full_name,
                    role="analyst"
                )

                if user_id:
                    # Auto-login newly registered user
                    session.clear()
                    session["user_id"] = user_id
                    session["username"] = candidate_username
                    session["full_name"] = full_name
                    session["email"] = email
                    session["role"] = "analyst"

                    if request.is_json:
                        return jsonify({
                            "status": "success",
                            "message": "Account created successfully.",
                            "redirect": url_for("index")
                        })
                    return redirect(url_for("index"))
                else:
                    error = "Failed to create account. Please try again."

        if request.is_json and error:
            return jsonify({"status": "error", "message": error}), 400

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Render login page and authenticate users."""
    if "user_id" in session:
        return redirect(url_for("index"))

    error = None
    success = request.args.get("registered")

    if request.method == "POST":
        if request.is_json:
            data = request.get_json() or {}
            identifier = data.get("email") or data.get("username") or ""
            password = data.get("password") or ""
        else:
            identifier = request.form.get("email") or request.form.get("username") or ""
            password = request.form.get("password") or ""

        if not identifier or not password:
            error = "Please enter both email address and password."
        else:
            # Check user existence for specific feedback
            existing = db.get_user_by_username_or_email(identifier)
            if not existing:
                error = "No account found with this email address. Please sign up."
            else:
                user = db.verify_user(identifier, password)
                if user:
                    session.clear()
                    session["user_id"] = user["user_id"]
                    session["username"] = user["username"]
                    session["full_name"] = user.get("full_name") or user["username"]
                    session["email"] = user.get("email")
                    session["role"] = user.get("role", "analyst")

                    next_page = request.args.get("next") or request.form.get("next")
                    if not next_page or not next_page.startswith("/") or next_page.startswith("//"):
                        next_page = url_for("index")

                    if request.is_json:
                        return jsonify({"status": "success", "redirect": next_page, "user": user})
                    return redirect(next_page)
                else:
                    error = "Incorrect password. Please try again."

        if request.is_json:
            return jsonify({"status": "error", "message": error}), 401

    return render_template("login.html", error=error, success=success)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Log out current user and clear session."""
    session.clear()
    if request.is_json:
        resp = jsonify({"status": "success", "message": "Successfully logged out."})
    else:
        resp = redirect(url_for("login"))
    
    # Explicitly invalidate session cookie and purge cache
    resp.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/")
@login_required
def index():
    """Render main DFIR dashboard view."""
    current_user = {
        "user_id": session.get("user_id"),
        "username": session.get("username", "Analyst"),
        "full_name": session.get("full_name") or session.get("username", "Analyst"),
        "email": session.get("email", ""),
        "role": session.get("role", "analyst")
    }
    return render_template("index.html", user=current_user)




# ============================================================================
# Phase 2 — Secure Evidence Upload & File/Folder Scanning
# ============================================================================

EVIDENCE_VAULT = os.environ.get("EVIDENCE_VAULT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_vault"))
os.makedirs(EVIDENCE_VAULT, exist_ok=True)


@app.route("/api/scan/upload", methods=["POST"])
@login_required
def upload_and_scan_evidence():
    """
    Handle secure file upload from the browser's native Windows File Explorer picker.
    Stores the evidence in an isolated, read-only evidence vault and executes
    the full TeamMember1 read-only forensic inspection, ML prediction, SQLite storage,
    and PDF report generation linked to the authenticated user.
    """
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded in request."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({"status": "error", "message": "No evidence file selected."}), 400

    raw_filename = uploaded_file.filename
    # Prevent path traversal attacks
    clean_filename = os.path.basename(raw_filename.replace("\\", "/"))
    if not clean_filename or clean_filename in (".", ".."):
        return jsonify({"status": "error", "message": "Invalid or unsafe filename."}), 400

    try:
        import uuid
        scan_vault_dir = os.path.join(EVIDENCE_VAULT, str(uuid.uuid4())[:8])
        os.makedirs(scan_vault_dir, exist_ok=True)
        staged_path = os.path.join(scan_vault_dir, clean_filename)

        # Save evidence file safely
        uploaded_file.save(staged_path)

        # Enforce strict read-only attribute on saved evidence file
        try:
            os.chmod(staged_path, 0o444)
            if sys.platform == "win32":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(staged_path, 0x01)  # FILE_ATTRIBUTE_READONLY
        except Exception:
            pass

        user_id = session.get("user_id")

        # Execute single file forensic scan linked to authenticated user
        result = run_single_file_scan(staged_path, db_path=db.db_path, generate_pdf=True, user_id=user_id)
        meta = dict(result.get("metadata") or result.get("file_info") or {})
        if "sha256_hash" in meta and "sha256" not in meta:
            meta["sha256"] = meta["sha256_hash"]

        return jsonify({
            "status": "success",
            "success": True,
            "result": result,
            "scan_id": result.get("scan_id"),
            "risk_level": result.get("risk_level"),
            "file_info": meta
        })

    except Exception as e:
        return jsonify({"status": "error", "success": False, "message": f"Scan failed: {str(e)}"}), 500


@app.route("/api/scan/upload-folder", methods=["POST"])
@login_required
def upload_and_scan_folder():
    """
    Handle multi-file / folder evidence upload from browser folder selection.
    Saves folder artifacts into an isolated evidence vault and runs forensic analysis.
    """
    uploaded_files = request.files.getlist("files")
    if not uploaded_files or len(uploaded_files) == 0 or uploaded_files[0].filename == "":
        return jsonify({"status": "error", "message": "No files found in folder upload."}), 400

    try:
        import uuid
        folder_vault_dir = os.path.join(EVIDENCE_VAULT, f"folder_{str(uuid.uuid4())[:8]}")
        os.makedirs(folder_vault_dir, exist_ok=True)

        staged_files = []
        for file_obj in uploaded_files:
            rel_path = file_obj.filename.replace("\\", "/").strip("/")
            # Basic path traversal guard
            safe_rel_parts = [p for p in rel_path.split("/") if p not in ("", ".", "..")]
            if not safe_rel_parts:
                continue
            dest_path = os.path.join(folder_vault_dir, *safe_rel_parts)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            file_obj.save(dest_path)
            staged_files.append(dest_path)

        if not staged_files:
            return jsonify({"status": "error", "message": "No valid files could be extracted from folder."}), 400

        user_id = session.get("user_id")

        # Scan the folder using directory collector and pipeline
        file_collector = FileCollector()
        scanned_files = file_collector.scan_directory(folder_vault_dir)

        result = run_pipeline(
            target_type="filesystem",
            target_path=folder_vault_dir,
            files=scanned_files,
            event_logs=[],
            registry_keys=[],
            memory_artifacts=[],
            db_path=DEFAULT_DB_PATH,
            user_id=user_id
        )

        return jsonify({
            "status": "success",
            "scan_id": result.scan_id,
            "risk_score": result.risk_score,
            "total_files": len(staged_files)
        })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Folder scan failed: {str(e)}"}), 500


@app.route("/api/scan/file", methods=["POST"])
@login_required
def scan_selected_file():
    """
    Scan a local evidence file path in strict READ-ONLY mode.
    Maintained for CLI compatibility and direct local path queries.
    """
    data = request.get_json() or {}
    file_path = data.get("file_path")

    if not file_path or not os.path.exists(file_path):
        return jsonify({"status": "error", "message": f"Evidence file not found: {file_path}"}), 400

    try:
        user_id = session.get("user_id")
        result = run_single_file_scan(file_path, db_path=DEFAULT_DB_PATH, generate_pdf=True, user_id=user_id)
        return jsonify({"status": "success", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"}), 500


# ============================================================================
# Phase 2 — PDF Report Download & Generation (Persistent)
# ============================================================================

@app.route("/api/report/<scan_id>", methods=["GET"])
@login_required
def download_pdf_report(scan_id):
    """
    Generate or retrieve and download the forensic PDF report for a scan session.
    Strictly enforces authenticated user data isolation.
    If the report file is missing on the filesystem (e.g., after Render container restart),
    dynamically regenerates the PDF with 100% fidelity from the immutable database record.
    """
    user_id = session.get("user_id")
    user_role = session.get("role", "analyst")
    effective_user_id = None if user_role == "admin" else user_id

    # Authorize scan access (returns None if scan does not exist or belongs to another user)
    scan = db.get_scan(scan_id, user_id=effective_user_id)
    if not scan:
        app.logger.warning(f"[SECURITY EVENT] Unauthorized report access attempt: user_id={user_id}, scan_id='{scan_id}', endpoint='{request.path}'")
        return jsonify({"status": "error", "message": "Scan report not found or access denied."}), 404

    pdf_filename = f"report_{scan_id}.pdf"
    os.makedirs(REPORTS_DIR, exist_ok=True)
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    # If PDF already cached on disk, send it directly
    if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename, mimetype="application/pdf")

    # If PDF not on disk (e.g. freshly restarted server/Render deploy), regenerate dynamically from DB snapshot
    summary = scan.get("summary") or {}
    findings = db.get_findings(scan_id, user_id=effective_user_id)
    features = db.get_features(scan_id, user_id=effective_user_id)

    # Use complete result JSON if stored, otherwise construct from fields
    if scan.get("result"):
        scan_data = scan["result"]
    else:
        file_display = scan.get("filename") or summary.get("file_name") or os.path.basename(scan.get("target_path", "Evidence"))
        scan_data = {
            "scan_id": scan_id,
            "scan_date": scan.get("start_time", ""),
            "file_name": file_display,
            "file_path": scan.get("target_path", "N/A"),
            "file_size": scan.get("file_size") or summary.get("file_size", 0),
            "risk_score": scan.get("risk_score", 0.0),
            "risk_level": scan.get("risk_level") or summary.get("risk_level", "LOW"),
            "ml_prediction": scan.get("ml_prediction") or summary.get("ml_prediction", "Normal"),
            "metadata": {
                "created_time": summary.get("created_time", "-"),
                "modified_time": summary.get("modified_time", "-"),
                "accessed_time": summary.get("accessed_time", "-"),
                "file_attributes": summary.get("file_attributes", []),
                "md5_hash": summary.get("md5") or summary.get("md5_hash") or "N/A",
                "sha256_hash": scan.get("sha256_hash") or summary.get("sha256") or summary.get("sha256_hash") or "N/A"
            },
            "signature": {
                "actual_type": summary.get("signature_type", "Unknown"),
                "claimed_extension": scan.get("file_type") or summary.get("extension", ""),
                "extension_match": summary.get("extension_match", True)
            },
            "findings": findings,
            "features": features
        }

    try:
        generate_forensic_pdf_report(scan_data, pdf_path)
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename, mimetype="application/pdf")
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to generate report: {str(e)}"}), 500


# ============================================================================
# Scan History & Management API (Persistent & User-Isolated)
# ============================================================================

@app.route("/api/scans", methods=["GET"])
@app.route("/api/history", methods=["GET"])
@login_required
def get_scans():
    """
    Retrieve list of historical scans from persistent database.
    Includes user data isolation, searching, filtering, sorting, and pagination.
    """
    user_id = session.get("user_id")
    user_role = session.get("role", "analyst")

    # Admins can optionally see all scans if requested, otherwise isolated to authenticated user
    effective_user_id = None if (user_role == "admin" and request.args.get("all_users") == "true") else user_id

    search = request.args.get("search", "").strip()
    risk_level = request.args.get("risk_level", "").strip()
    status = request.args.get("status", "").strip()
    sort_by = request.args.get("sort", "newest").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(100, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        page = 1
        limit = 50

    offset = (page - 1) * limit

    scans = db.list_scans(
        user_id=effective_user_id,
        limit=limit,
        offset=offset,
        search=search,
        risk_level=risk_level,
        status=status,
        sort_by=sort_by
    )

    total_count = db.count_scans(
        user_id=effective_user_id,
        search=search,
        risk_level=risk_level,
        status=status
    )

    stats = db.get_user_scan_stats(user_id=effective_user_id)

    return jsonify({
        "status": "success",
        "success": True,
        "scans": scans,
        "total": total_count,
        "page": page,
        "limit": limit,
        "total_pages": max(1, (total_count + limit - 1) // limit),
        "pagination": {
            "page": page,
            "limit": limit,
            "total_records": total_count,
            "total_pages": max(1, (total_count + limit - 1) // limit)
        },
        "stats": stats
    })


@app.route("/api/scan/<scan_id>", methods=["GET"])
@login_required
def get_scan_details(scan_id):
    """
    Retrieve full details, findings, and features for a specific scan.
    Enforces user data isolation.
    """
    user_id = session.get("user_id")
    user_role = session.get("role", "analyst")
    effective_user_id = None if user_role == "admin" else user_id

    scan = db.get_scan(scan_id, user_id=effective_user_id)
    if not scan:
        app.logger.warning(f"[SECURITY EVENT] Unauthorized scan details access attempt: user_id={user_id}, scan_id='{scan_id}', endpoint='{request.path}'")
        return jsonify({"status": "error", "success": False, "message": "Scan record not found or access denied."}), 404

    findings = db.get_findings(scan_id, user_id=effective_user_id)
    features = db.get_features(scan_id, user_id=effective_user_id)

    # Extract real trained model metadata & feature weights
    try:
        from ml.predict import get_model_metadata
        model_metadata = get_model_metadata()
    except Exception as e:
        app.logger.warning(f"Error loading model metadata: {e}")
        model_metadata = None

    return jsonify({
        "status": "success",
        "success": True,
        "scan": scan,
        "findings": findings,
        "features": features,
        "model_metadata": model_metadata,
        "result": scan.get("result")
    })


@app.route("/api/ml/model", methods=["GET"])
@login_required
def get_ml_model_info():
    """
    Retrieve real Random Forest model architecture metadata and exact feature importances.
    Provides true model explainability weights directly from sklearn.
    """
    try:
        from ml.predict import get_model_metadata
        metadata = get_model_metadata()
        return jsonify({
            "status": "success",
            "success": True,
            "model": metadata
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
@login_required
def delete_scan_record(scan_id):
    """
    Safely delete an individual scan history record and its cascaded findings/features.
    Enforces strict user ownership verification.
    """
    user_id = session.get("user_id")
    user_role = session.get("role", "analyst")
    effective_user_id = None if user_role == "admin" else user_id

    # Verify ownership before deletion
    scan = db.get_scan(scan_id, user_id=effective_user_id)
    if not scan:
        app.logger.warning(f"[SECURITY EVENT] Unauthorized scan deletion attempt: user_id={user_id}, scan_id='{scan_id}', endpoint='{request.path}'")
        return jsonify({"status": "error", "success": False, "message": "Scan record not found or access denied."}), 404

    success = db.delete_scan(scan_id, user_id=effective_user_id)
    if success:
        # Optionally clean up cached PDF report
        pdf_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
            except Exception:
                pass

        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Scan '{scan.get('filename') or scan_id}' has been permanently removed from your history."
        })
    else:
        return jsonify({"status": "error", "success": False, "message": "Failed to delete scan record."}), 500


@app.route("/api/stats", methods=["GET"])
@login_required
def get_user_stats():
    """Retrieve aggregated dashboard metrics for the authenticated user."""
    user_id = session.get("user_id")
    stats = db.get_user_scan_stats(user_id=user_id)
    return jsonify({"status": "success", "stats": stats})


@app.route("/api/scan/trigger", methods=["POST"])
@login_required
def trigger_scan():
    """Trigger a batch scan (demo simulation, directory scan, or live system audit)."""
    data = request.get_json() or {}
    scan_type = data.get("type", "demo")
    target_path = data.get("target_path", "")
    user_id = session.get("user_id")

    if scan_type == "demo":
        simulator = ForensicSandboxSimulator()
        sandbox_path, event_logs, registry_artifacts, memory_artifacts = simulator.create_simulated_environment()
        file_collector = FileCollector()
        files = file_collector.scan_directory(sandbox_path)

        result = run_pipeline(
            target_type="demo_simulation",
            target_path=sandbox_path,
            files=files,
            event_logs=event_logs,
            registry_keys=registry_artifacts,
            memory_artifacts=memory_artifacts,
            db_path=DEFAULT_DB_PATH,
            user_id=user_id
        )
        return jsonify({"status": "success", "scan_id": result.scan_id, "risk_score": result.risk_score})

    elif scan_type == "directory":
        if not target_path or not os.path.exists(target_path):
            return jsonify({"status": "error", "message": "Invalid directory path"}), 400

        file_collector = FileCollector()
        files = file_collector.scan_directory(target_path)
        result = run_pipeline(
            target_type="filesystem",
            target_path=target_path,
            files=files,
            event_logs=[],
            registry_keys=[],
            memory_artifacts=[],
            db_path=DEFAULT_DB_PATH,
            user_id=user_id
        )
        return jsonify({"status": "success", "scan_id": result.scan_id, "risk_score": result.risk_score})

    elif scan_type == "live":
        file_collector = FileCollector()
        files = file_collector.scan_directory(target_path or os.getcwd())
        el_collector = EventLogCollector()
        event_logs = el_collector.collect_live_logs()
        reg_collector = RegistryCollector()
        registry_keys = reg_collector.collect_anti_forensic_keys()

        result = run_pipeline(
            target_type="live_system",
            target_path=target_path or "Local Host",
            files=files,
            event_logs=event_logs,
            registry_keys=registry_keys,
            memory_artifacts=[],
            db_path=DEFAULT_DB_PATH,
            user_id=user_id
        )
        return jsonify({"status": "success", "scan_id": result.scan_id, "risk_score": result.risk_score})

    return jsonify({"status": "error", "message": "Unknown scan type"}), 400


@app.route("/api/features/export/<scan_id>", methods=["GET"])
@login_required
def export_features_csv(scan_id):
    """Export and download scan features as CSV with user authorization check."""
    user_id = session.get("user_id")
    user_role = session.get("role", "analyst")
    effective_user_id = None if user_role == "admin" else user_id

    scan = db.get_scan(scan_id, user_id=effective_user_id)
    if not scan:
        app.logger.warning(f"[SECURITY EVENT] Unauthorized CSV export attempt: user_id={user_id}, scan_id='{scan_id}', endpoint='{request.path}'")
        return jsonify({"status": "error", "message": "Scan record not found or access denied."}), 404

    df = db.get_features_dataframe(scan_id=scan_id, user_id=effective_user_id)
    if df.empty:
        return jsonify({"status": "error", "message": "No features found"}), 404

    csv_path = f"export_{scan_id}.csv"
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True, download_name=f"features_{scan_id}.csv")



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[+] Anti-Forensics Detection Web Dashboard running on http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
