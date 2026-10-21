"""
NetScope: Real-Time Network Packet Analyzer and Traffic Intelligence Dashboard
Flask Application Entry Point
"""

import os
import sys
from flask import Flask, render_template, jsonify
from config import Config
from routes.api import api_bp
from storage.database import DatabaseManager


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required directories exist
    os.makedirs(app.config.get("UPLOAD_FOLDER", "data/uploads"), exist_ok=True)
    db_path = app.config.get("DATABASE_PATH", "storage/netscope.db")
    db_dir = os.path.dirname(db_path) if db_path != ":memory:" else ""
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # Initialize SQLite database
    DatabaseManager(db_path)

    # Register blueprints
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"error": "File size exceeds the 50 MB upload limit."}), 413

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "An internal server error occurred."}), 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] NetScope running on http://127.0.0.1:{port}")
    print("[*] Academic Computer Networks Mini-Project")
    print("[*] Ready for offline PCAP ingestion and live packet analysis.")
    app.run(host="127.0.0.1", port=port, debug=False)
