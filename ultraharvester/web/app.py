"""
UltraHarvester Web Dashboard — Flask application
"""

import os
import json
import glob
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from flask_cors import CORS

try:
    from flask_socketio import SocketIO, emit
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False


def create_app(output_dir: str = "./output") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.urandom(32)
    app.config["OUTPUT_DIR"] = output_dir
    CORS(app)

    if HAS_SOCKETIO:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
        app.socketio = socketio
    else:
        app.socketio = None

    active_scans: Dict[str, Dict] = {}

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/scan", methods=["GET", "POST"])
    def scan_page():
        if request.method == "POST":
            data = request.get_json() or request.form.to_dict()
            target = data.get("target", "").strip()
            if not target:
                return jsonify({"error": "Target is required"}), 400

            scan_id = f"scan_{int(time.time())}"
            config_data = {
                "target": target,
                "modules": data.get("modules", "all"),
                "output_dir": output_dir,
                "output_formats": data.get("formats", "json,html").split(","),
                "threads": int(data.get("threads", 20)),
                "port_range": data.get("port_range", "1-1000"),
                "shodan_api_key": data.get("shodan_key", "") or os.getenv("SHODAN_API_KEY"),
                "hibp_api_key": data.get("hibp_key", "") or os.getenv("HIBP_API_KEY"),
            }
            active_scans[scan_id] = {
                "id": scan_id,
                "target": target,
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "progress": 0,
                "results": None,
                "logs": [],
            }

            def run_scan():
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
                    from ultraharvester.utils.config import Config
                    from ultraharvester.core.scanner import Scanner

                    cfg = Config()
                    cfg.target = config_data["target"]
                    cfg.domain = config_data["target"]
                    cfg.output_dir = config_data["output_dir"]
                    cfg.output_formats = config_data["output_formats"]
                    cfg.threads = config_data["threads"]
                    cfg.port_range = config_data["port_range"]
                    if config_data.get("shodan_api_key"):
                        cfg.shodan_api_key = config_data["shodan_api_key"]
                    if config_data.get("hibp_api_key"):
                        cfg.hibp_api_key = config_data["hibp_api_key"]

                    modules = config_data["modules"]
                    if modules == "all":
                        cfg.modules = ["emails", "dns", "ports", "metadata", "leaks", "web", "ai"]
                    else:
                        cfg.modules = [m.strip() for m in modules.split(",")]

                    scanner = Scanner(cfg)
                    results = scanner.run()
                    active_scans[scan_id]["results"] = results
                    active_scans[scan_id]["status"] = "completed"
                    active_scans[scan_id]["progress"] = 100
                except Exception as e:
                    active_scans[scan_id]["status"] = "error"
                    active_scans[scan_id]["error"] = str(e)

            t = threading.Thread(target=run_scan, daemon=True)
            t.start()
            return jsonify({"scan_id": scan_id, "status": "started"})

        return render_template("scan.html")

    @app.route("/api/scan/<scan_id>/status")
    def scan_status(scan_id):
        scan = active_scans.get(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify({
            "id": scan_id,
            "status": scan["status"],
            "progress": scan["progress"],
            "target": scan["target"],
            "start_time": scan["start_time"],
        })

    @app.route("/api/scan/<scan_id>/results")
    def scan_results(scan_id):
        scan = active_scans.get(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if scan["status"] != "completed":
            return jsonify({"status": scan["status"]}), 202
        return jsonify(scan["results"])

    @app.route("/results")
    def results_page():
        scan_files = sorted(
            glob.glob(os.path.join(output_dir, "*.json")),
            key=os.path.getmtime, reverse=True
        )
        scans = []
        for f in scan_files[:20]:
            try:
                with open(f) as fp:
                    data = json.load(fp)
                scans.append({
                    "file": f,
                    "filename": os.path.basename(f),
                    "target": data.get("target", "unknown"),
                    "scan_start": data.get("scan_start", ""),
                    "risk_score": data.get("ai", {}).get("risk_score", 0),
                    "risk_level": data.get("ai", {}).get("risk_level", "UNKNOWN"),
                    "emails": len(data.get("emails", {}).get("emails", [])),
                    "subdomains": len(data.get("dns", {}).get("subdomains", [])),
                    "ports": len(data.get("ports", {}).get("open_ports", [])),
                    "breaches": len(data.get("leaks", {}).get("breaches", [])),
                })
            except Exception:
                pass
        return render_template("results.html", scans=scans)

    @app.route("/results/<path:filename>")
    def result_detail(filename):
        filepath = os.path.join(output_dir, filename)
        if not os.path.exists(filepath) or not filepath.endswith(".json"):
            return "File not found", 404
        try:
            with open(filepath) as f:
                data = json.load(f)
            return render_template("result_detail.html", data=data, filename=filename)
        except Exception as e:
            return f"Error reading file: {e}", 500

    @app.route("/download/<path:filename>")
    def download_file(filename):
        filepath = os.path.join(output_dir, filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        return "File not found", 404

    @app.route("/api/stats")
    def api_stats():
        scan_files = glob.glob(os.path.join(output_dir, "*.json"))
        total_emails = 0
        total_subdomains = 0
        total_breaches = 0
        risk_scores = []
        for f in scan_files:
            try:
                with open(f) as fp:
                    data = json.load(fp)
                total_emails += len(data.get("emails", {}).get("emails", []))
                total_subdomains += len(data.get("dns", {}).get("subdomains", []))
                total_breaches += len(data.get("leaks", {}).get("breaches", []))
                rs = data.get("ai", {}).get("risk_score", 0)
                if rs:
                    risk_scores.append(rs)
            except Exception:
                pass
        return jsonify({
            "total_scans": len(scan_files),
            "total_emails": total_emails,
            "total_subdomains": total_subdomains,
            "total_breaches": total_breaches,
            "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0,
            "active_scans": len([s for s in active_scans.values() if s["status"] == "running"]),
        })

    @app.route("/api/graph/<path:filename>")
    def api_graph(filename):
        filepath = os.path.join(output_dir, filename)
        if not os.path.exists(filepath):
            return jsonify({"error": "File not found"}), 404
        try:
            with open(filepath) as f:
                data = json.load(f)
            nodes = []
            edges = []
            target = data.get("target", "")
            nodes.append({"id": target, "label": target, "type": "domain", "size": 30})

            for sub in data.get("dns", {}).get("subdomains", [])[:30]:
                sub_name = sub.get("subdomain", "")
                nodes.append({"id": sub_name, "label": sub_name, "type": "subdomain", "size": 15})
                edges.append({"from": target, "to": sub_name, "type": "subdomain"})

            for email in data.get("emails", {}).get("emails", [])[:20]:
                nodes.append({"id": email, "label": email, "type": "email", "size": 10})
                edges.append({"from": target, "to": email, "type": "email"})

            for employee in data.get("emails", {}).get("employees", [])[:15]:
                nodes.append({"id": employee, "label": employee, "type": "person", "size": 8})

            return jsonify({"nodes": nodes, "edges": edges})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def run_web(host: str = "0.0.0.0", port: int = 5000, output_dir: str = "./output"):
    app = create_app(output_dir)
    print(f"\n[UltraHarvester] Web Dashboard running at http://localhost:{port}")
    print(f"[UltraHarvester] Output directory: {output_dir}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
