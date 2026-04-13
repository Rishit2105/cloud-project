from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import pandas as pd
import sqlite3
import hashlib
import uuid
import json
import os
import random
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timedelta
from dotenv import load_dotenv

# ═══════════════════════════════════════════════════════════════════
# App Setup
# ═══════════════════════════════════════════════════════════════════

app = FastAPI(title="Multi-Cloud Cost Optimization Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db.sqlite3"
ENV_PATH = BASE_DIR / ".env"

# ═══════════════════════════════════════════════════════════════════
# Database
# ═══════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 100_000
    ).hex()


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS user_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            enabled_clouds TEXT DEFAULT '["AWS","Azure","GCP"]',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()

    # Seed default admin
    salt = uuid.uuid4().hex
    pw_hash = hash_password("admin123", salt)
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            ("admin", pw_hash, salt),
        )
        conn.execute(
            "INSERT INTO user_config (user_id, enabled_clouds) VALUES (?, ?)",
            (cur.lastrowid, '["AWS","Azure","GCP"]'),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()


init_db()

# ═══════════════════════════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════════════════════════

sessions: dict = {}  # token -> {user_id, username}


def get_current_user(authorization: Optional[str] = None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return sessions[token]

# ═══════════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════════

class AuthRequest(BaseModel):
    username: str
    password: str


class ConfigSaveRequest(BaseModel):
    enabled_clouds: List[str]
    credentials: dict = {}


class TestConnectionRequest(BaseModel):
    provider: str
    credentials: dict

# ═══════════════════════════════════════════════════════════════════
# Page Serving
# ═══════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def serve_login():
    return (BASE_DIR / "login.html").read_text(encoding="utf-8")


@app.get("/configure", response_class=HTMLResponse)
def serve_configure():
    return (BASE_DIR / "configure.html").read_text(encoding="utf-8")


@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    return (BASE_DIR / "frontend.html").read_text(encoding="utf-8")

# ═══════════════════════════════════════════════════════════════════
# Auth Endpoints
# ═══════════════════════════════════════════════════════════════════

@app.post("/auth/login")
def login(req: AuthRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (req.username,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if hash_password(req.password, row["salt"]) != row["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = uuid.uuid4().hex
    sessions[token] = {"user_id": row["id"], "username": row["username"]}
    return {"token": token, "username": row["username"]}


@app.post("/auth/register")
def register(req: AuthRequest):
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    salt = uuid.uuid4().hex
    pw_hash = hash_password(req.password, salt)

    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (req.username, pw_hash, salt),
        )
        conn.execute(
            "INSERT INTO user_config (user_id, enabled_clouds) VALUES (?, ?)",
            (cur.lastrowid, '["AWS","Azure","GCP"]'),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    conn.close()
    return {"message": "Account created successfully"}


@app.get("/auth/me")
def auth_me(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    return {"username": user["username"], "user_id": user["user_id"]}


@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        sessions.pop(token, None)
    return {"message": "Logged out"}

# ═══════════════════════════════════════════════════════════════════
# Configuration Endpoints
# ═══════════════════════════════════════════════════════════════════

@app.post("/config/save")
def save_config(req: ConfigSaveRequest, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)

    conn = get_db()
    conn.execute(
        "UPDATE user_config SET enabled_clouds = ? WHERE user_id = ?",
        (json.dumps(req.enabled_clouds), user["user_id"]),
    )
    conn.commit()
    conn.close()

    # Write credentials to .env
    env_lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            env_lines = f.readlines()

    cloud_prefixes = ("AWS_", "AZURE_", "GCP_")
    env_lines = [
        l for l in env_lines if not any(l.strip().startswith(p) for p in cloud_prefixes)
    ]

    for key, value in req.credentials.items():
        if value and value.strip():
            env_lines.append(f"{key}={value.strip()}\n")

    with open(ENV_PATH, "w") as f:
        f.writelines(env_lines)

    # Invalidate data cache so next request fetches fresh data
    data_cache["data"] = None
    data_cache["timestamp"] = None

    return {"message": "Configuration saved", "enabled_clouds": req.enabled_clouds}


@app.get("/config/load")
def load_config(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)

    conn = get_db()
    config = conn.execute(
        "SELECT * FROM user_config WHERE user_id = ?", (user["user_id"],)
    ).fetchone()
    conn.close()

    enabled = json.loads(config["enabled_clouds"]) if config else ["AWS", "Azure", "GCP"]

    # Load raw credentials (for pre-filling fields, masked)
    creds = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    if any(k.startswith(p) for p in ("AWS_", "AZURE_", "GCP_")):
                        creds[k] = v[:4] + "••••" + v[-4:] if len(v) > 8 else "••••"

    return {"enabled_clouds": enabled, "credentials": creds}


@app.post("/config/test-connection")
def test_connection(req: TestConnectionRequest):
    provider = req.provider.upper()
    creds = req.credentials

    if provider == "AWS":
        try:
            import boto3

            client = boto3.client(
                "sts",
                aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID", ""),
                aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY", ""),
                region_name=creds.get("AWS_REGION", "us-east-1"),
            )
            identity = client.get_caller_identity()
            return {
                "status": "connected",
                "message": f"Connected as {identity['Arn']}",
            }
        except ImportError:
            return {
                "status": "sdk_missing",
                "message": "boto3 not installed. Run: pip install boto3",
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    elif provider == "AZURE":
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient

            credential = ClientSecretCredential(
                tenant_id=creds.get("AZURE_TENANT_ID", ""),
                client_id=creds.get("AZURE_CLIENT_ID", ""),
                client_secret=creds.get("AZURE_CLIENT_SECRET", ""),
            )
            client = ResourceManagementClient(
                credential, creds.get("AZURE_SUBSCRIPTION_ID", "")
            )
            list(client.resource_groups.list())
            return {"status": "connected", "message": "Connected to Azure successfully"}
        except ImportError:
            return {
                "status": "sdk_missing",
                "message": "Azure SDK not installed. Run: pip install azure-identity azure-mgmt-resource",
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    elif provider == "GCP":
        try:
            from google.oauth2 import service_account
            from google.cloud import resourcemanager_v3

            sa_key_path = creds.get("GCP_SERVICE_ACCOUNT_KEY", "")
            project_id = creds.get("GCP_PROJECT_ID", "")
            if sa_key_path and os.path.exists(sa_key_path):
                credentials = service_account.Credentials.from_service_account_file(
                    sa_key_path
                )
                client = resourcemanager_v3.ProjectsClient(credentials=credentials)
                project = client.get_project(name=f"projects/{project_id}")
                return {
                    "status": "connected",
                    "message": f"Connected to project: {project.display_name}",
                }
            else:
                return {
                    "status": "error",
                    "message": "Service Account Key file not found at the given path",
                }
        except ImportError:
            return {
                "status": "sdk_missing",
                "message": "Google Cloud SDK not installed. Run: pip install google-cloud-resource-manager google-auth",
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    return {"status": "error", "message": f"Unknown provider: {provider}"}

# ═══════════════════════════════════════════════════════════════════
# Cloud Data Fetching (Live APIs → Fallback to data.csv)
# ═══════════════════════════════════════════════════════════════════

def _load_env_creds() -> dict:
    creds = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    creds[k] = v
    return creds


def fetch_aws_costs(creds: dict):
    """Pull last-30-day costs from AWS Cost Explorer."""
    try:
        import boto3

        ce = boto3.client(
            "ce",
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            region_name=creds.get("AWS_REGION", "us-east-1"),
        )
        end = datetime.utcnow()
        start = end - timedelta(days=30)
        resp = ce.get_cost_and_usage(
            TimePeriod={
                "Start": start.strftime("%Y-%m-%d"),
                "End": end.strftime("%Y-%m-%d"),
            },
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        records = []
        for r in resp.get("ResultsByTime", []):
            dt = r["TimePeriod"]["Start"]
            for g in r.get("Groups", []):
                cost = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if cost > 0:
                    records.append(
                        {
                            "date": dt,
                            "cloud": "AWS",
                            "service": g["Keys"][0],
                            "cost": round(cost, 2),
                            "cpu_usage": random.randint(5, 85),
                        }
                    )
        return records
    except Exception as e:
        print(f"[AWS] Live fetch failed: {e}")
    return None


def fetch_azure_costs(creds: dict):
    """Pull last-30-day costs from Azure Cost Management."""
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.mgmt.costmanagement import CostManagementClient
        from azure.mgmt.costmanagement.models import (
            QueryDefinition,
            QueryTimePeriod,
            QueryDataset,
            QueryAggregation,
            QueryGrouping,
        )

        tenant_id = creds.get("AZURE_TENANT_ID")
        client_id = creds.get("AZURE_CLIENT_ID")
        client_secret = creds.get("AZURE_CLIENT_SECRET")
        subscription_id = creds.get("AZURE_SUBSCRIPTION_ID")

        if tenant_id and client_id and client_secret:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            credential = DefaultAzureCredential()

        client = CostManagementClient(credential)
        scope = f"/subscriptions/{subscription_id}" if subscription_id else f"/subscriptions/{creds.get('AZURE_SUBSCRIPTION_ID')}"

        end = datetime.utcnow()
        start = end - timedelta(days=30)

        query = QueryDefinition(
            type="ActualCost",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=start, to=end),
            dataset=QueryDataset(
                granularity="Daily",
                aggregation={
                    "totalCost": QueryAggregation(name="Cost", function="Sum")
                },
                grouping=[QueryGrouping(type="Dimension", name="ServiceName")],
            ),
        )
        result = client.query.usage(scope=scope, parameters=query)

        records = []
        for row in result.rows:
            cost = float(row[0])
            if cost > 0:
                records.append(
                    {
                        "date": str(row[2])[:10]
                        if len(row) > 2
                        else start.strftime("%Y-%m-%d"),
                        "cloud": "Azure",
                        "service": row[1],
                        "cost": round(cost, 2),
                        "cpu_usage": random.randint(5, 85),
                    }
                )
        return records
    except Exception as e:
        print(f"[Azure] Live fetch failed: {e}")
    return None


def fetch_gcp_costs(creds: dict):
    """Pull last-30-day costs from GCP BigQuery billing export."""
    try:
        from google.cloud import bigquery
        from google.oauth2 import service_account

        project_id = creds.get("GCP_PROJECT_ID")
        sa_key = creds.get("GCP_SERVICE_ACCOUNT_KEY")

        bq_creds = None
        if sa_key and os.path.exists(sa_key):
            bq_creds = service_account.Credentials.from_service_account_file(sa_key)
        
        client = bigquery.Client(project=project_id, credentials=bq_creds)
        start = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")

        query = f"""
            SELECT
                DATE(usage_start_time) AS date,
                service.description AS service,
                SUM(cost) AS cost
            FROM `{project_id}.billing_export.gcp_billing_export_v1*`
            WHERE usage_start_time >= '{start}'
            GROUP BY date, service
            HAVING cost > 0
            ORDER BY date DESC
        """
        records = []
        for row in client.query(query):
            records.append(
                {
                    "date": str(row.date),
                    "cloud": "GCP",
                    "service": row.service,
                    "cost": round(float(row.cost), 2),
                    "cpu_usage": random.randint(5, 85),
                }
            )
        return records
    except Exception as e:
        print(f"[GCP] Live fetch failed: {e}")
    return None


# ── Data cache ──────────────────────────────────────────────────
data_cache: dict = {"data": None, "timestamp": None, "sources": {}}

def get_cloud_data(enabled_clouds: List[str] | None = None):
    """Fetch data for each enabled cloud (live → fallback)."""
    global data_cache

    # 5-minute cache
    if data_cache["data"] is not None and data_cache["timestamp"]:
        age = (datetime.utcnow() - data_cache["timestamp"]).total_seconds()
        if age < 300:
            df = data_cache["data"]
            if enabled_clouds:
                df = df[df["cloud"].isin(enabled_clouds)]
            return df, data_cache["sources"]

    creds = _load_env_creds()
    all_records: list = []
    sources: dict = {}

    fetchers = {
        "AWS": fetch_aws_costs,
        "Azure": fetch_azure_costs,
        "GCP": fetch_gcp_costs,
    }

    df_fallback = None

    for cloud, fetcher in fetchers.items():
        if enabled_clouds and cloud not in enabled_clouds:
            continue
        live = fetcher(creds)
        if live is not None:
            all_records.extend(live)
            sources[cloud] = "live"
        else:
            try:
                if df_fallback is None:
                    csv_path = BASE_DIR / "data.csv"
                    df_fallback = pd.read_csv(csv_path)
                fb = df_fallback[df_fallback["cloud"] == cloud].to_dict("records")
                all_records.extend(fb)
                sources[cloud] = "demo"
            except Exception as e:
                print(f"[{cloud}] Failed to load fallback CSV: {e}")
                sources[cloud] = "error"

    df = pd.DataFrame(all_records) if all_records else pd.DataFrame(
        columns=["date", "cloud", "service", "cost", "cpu_usage"]
    )

    data_cache["data"] = df
    data_cache["timestamp"] = datetime.utcnow()
    data_cache["sources"] = sources

    if enabled_clouds:
        df = df[df["cloud"].isin(enabled_clouds)]
    return df, sources

# ═══════════════════════════════════════════════════════════════════
# Helper: get enabled clouds for the calling user
# ═══════════════════════════════════════════════════════════════════

def _enabled_clouds_for(authorization: Optional[str]) -> List[str]:
    try:
        user = get_current_user(authorization)
        conn = get_db()
        row = conn.execute(
            "SELECT enabled_clouds FROM user_config WHERE user_id = ?",
            (user["user_id"],),
        ).fetchone()
        conn.close()
        if row:
            return json.loads(row["enabled_clouds"])
    except Exception:
        pass
    return ["AWS", "Azure", "GCP"]

# ═══════════════════════════════════════════════════════════════════
# Data Endpoints
# ═══════════════════════════════════════════════════════════════════

@app.get("/costs")
def get_costs(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    df, _ = get_cloud_data(enabled)
    return df.to_dict(orient="records")


@app.get("/summary")
def get_summary(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    df, _ = get_cloud_data(enabled)
    if df.empty:
        return []
    summary = df.groupby("cloud")["cost"].sum().reset_index()
    summary.columns = ["cloud", "total_cost"]
    summary["total_cost"] = summary["total_cost"].round(2)
    return summary.to_dict(orient="records")


@app.get("/anomalies")
def get_anomalies(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    df, _ = get_cloud_data(enabled)
    if df.empty:
        return []

    avg_cost = df["cost"].mean()
    threshold = 1.5 * avg_cost
    anomalies_df = df[df["cost"] > threshold].copy()

    results = []
    for _, row in anomalies_df.iterrows():
        reason = "Unusual cost spike - check recent activity"
        service = str(row["service"]).lower()

        if any(kw in service for kw in ["compute", "ec2", "vm"]):
            if row["cpu_usage"] > 70:
                reason = "Compute scaling spike due to high load"
            elif row["cpu_usage"] < 20:
                reason = "High-cost idle resource - possible waste"
        elif any(kw in service for kw in ["db", "sql", "rds"]):
            reason = "Database job or migration activity"
        elif any(kw in service for kw in ["storage", "s3", "blob"]):
            reason = "Sudden data volume increase or backup"

        item = row.to_dict()
        item["reason"] = reason
        results.append(item)

    return results


@app.get("/recommendations")
def get_recommendations(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    df, _ = get_cloud_data(enabled)
    if df.empty:
        return []

    low_usage = df[df["cpu_usage"] < 10]
    recommendations = []
    for _, row in low_usage.iterrows():
        savings = round(row["cost"] * 0.4, 2)
        recommendations.append(
            {
                "service": row["service"],
                "cloud": row["cloud"],
                "cost": row["cost"],
                "cpu_usage": row["cpu_usage"],
                "estimated_savings": savings,
                "message": f"Low usage - downsize to save ${savings}",
            }
        )
    return recommendations


@app.get("/forecast")
def forecast(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    df, _ = get_cloud_data(enabled)
    if df.empty:
        return {"predicted_daily_cost": 0, "weekly_estimate": 0, "monthly_estimate": 0}

    df_sorted = df.sort_values("date")
    last_5 = df_sorted.tail(5)["cost"]
    trend = (last_5.iloc[-1] - last_5.iloc[0]) / len(last_5)
    predicted_next = last_5.mean() + trend

    return {
        "predicted_daily_cost": round(predicted_next, 2),
        "weekly_estimate": round(predicted_next * 7, 2),
        "monthly_estimate": round(predicted_next * 30, 2),
    }


@app.get("/best-cloud")
def best_cloud(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    df, _ = get_cloud_data(enabled)
    if df.empty:
        return {"best_cloud": "N/A", "total_cost": 0}

    summary = df.groupby("cloud")["cost"].sum()
    best = summary.idxmin()
    cost = round(summary.min(), 2)
    return {"best_cloud": best, "total_cost": cost}


@app.get("/data-sources")
def data_sources(authorization: Optional[str] = Header(None)):
    enabled = _enabled_clouds_for(authorization)
    _, sources = get_cloud_data(enabled)
    return {"sources": sources}


@app.post("/refresh-data")
def refresh_data(authorization: Optional[str] = Header(None)):
    get_current_user(authorization)
    data_cache["data"] = None
    data_cache["timestamp"] = None
    return {"message": "Cache cleared — data will refresh on next request"}