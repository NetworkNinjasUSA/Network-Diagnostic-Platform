"""Network Diagnostic Platform - Test Node Application."""
from fastapi import FastAPI, Depends, BackgroundTasks, Request, Response, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
import json
import os
import sys

# Add parent directory for shared imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from .config import get_config, NodeConfig
from .database import get_db, init_db, TestResult, CustomerToken
from .auth import (
    get_current_user, get_optional_user, require_role,
    create_access_token, create_refresh_token, authenticate_user,
    create_customer_token, validate_customer_token, get_customer_token_info,
    ensure_admin_exists
)
from .runners import (
    SpeedTestRunner, TracerouteRunner, MTRRunner, DNSRunner,
    TCPCheckRunner, SSLCheckRunner, IperfRunner, PacketCaptureRunner
)
from .runners.ping import ping_runner

from shared.models import (
    TestType, TestStatus, LoginRequest, TokenResponse,
    CustomerTokenCreate, CustomerTokenResponse, TestRequest
)
from shared.utils import get_client_ip, RateLimiter

# Initialize app
app = FastAPI(
    title="Network Diagnostic Platform - Node",
    description="Distributed network diagnostic test node",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiters
speedtest_limiter = RateLimiter(max_requests=10, window_seconds=60)
api_limiter = RateLimiter(max_requests=100, window_seconds=60)

# Runner instances
speedtest_runner = SpeedTestRunner()
traceroute_runner = TracerouteRunner()
mtr_runner = MTRRunner()
dns_runner = DNSRunner()
tcp_runner = TCPCheckRunner()
ssl_runner = SSLCheckRunner()
iperf_runner = IperfRunner()
capture_runner = PacketCaptureRunner()


@app.on_event("startup")
async def startup():
    """Initialize database and ensure admin exists."""
    init_db()
    db = next(get_db())
    ensure_admin_exists(db)
    db.close()


# ============== Authentication Endpoints ==============

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate and get access token."""
    user = authenticate_user(db, request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(user.username, user.role)
    refresh_token = create_refresh_token(user.username)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600
    )


@app.get("/api/auth/me")
async def get_me(user = Depends(get_current_user)):
    """Get current user info."""
    if user is None:
        return {"authenticated": False, "auth_required": get_config().require_auth}
    
    return {
        "authenticated": True,
        "username": user.username,
        "role": user.role
    }


# ============== Customer Token Endpoints ==============

@app.post("/api/tokens", response_model=CustomerTokenResponse)
async def create_token(
    token_config: CustomerTokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_role("engineer"))
):
    """Create a customer test token."""
    token = create_customer_token(
        db,
        customer_id=token_config.customer_id,
        expires_hours=token_config.expires_hours,
        max_uses=token_config.max_uses,
        note=token_config.note,
        created_by=user.username if user else None
    )
    
    # Build test URL
    host = request.headers.get("host", "localhost:8000")
    protocol = "https" if request.url.scheme == "https" else "http"
    test_url = f"{protocol}://{host}/speedtest?token={token.token}"
    
    return CustomerTokenResponse(
        id=token.id,
        token=token.token,
        customer_id=token.customer_id,
        expires_at=token.expires_at,
        max_uses=token.max_uses,
        use_count=token.use_count,
        created_at=token.created_at,
        test_url=test_url
    )


@app.get("/api/tokens")
async def list_tokens(
    db: Session = Depends(get_db),
    user = Depends(require_role("engineer"))
):
    """List all customer tokens."""
    tokens = db.query(CustomerToken).order_by(CustomerToken.created_at.desc()).all()
    return [
        {
            "id": t.id,
            "token": t.token[:8] + "...",  # Partial token for display
            "customer_id": t.customer_id,
            "expires_at": t.expires_at.isoformat(),
            "max_uses": t.max_uses,
            "use_count": t.use_count,
            "created_at": t.created_at.isoformat(),
            "expired": t.expires_at < datetime.utcnow(),
            "exhausted": t.use_count >= t.max_uses
        }
        for t in tokens
    ]


@app.delete("/api/tokens/{token_id}")
async def delete_token(
    token_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_role("engineer"))
):
    """Delete/revoke a customer token."""
    token = db.query(CustomerToken).filter(CustomerToken.id == token_id).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    db.delete(token)
    db.commit()
    return {"deleted": token_id}


# ============== Speed Test Endpoints ==============

@app.get("/api/speedtest/ping")
async def speedtest_ping():
    """Ping endpoint for latency measurement."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/speedtest/download")
async def speedtest_download(size: int = 1048576):
    """Generate data for download speed test."""
    size = min(size, 10485760)  # Cap at 10MB
    data = os.urandom(size)
    return Response(content=data, media_type="application/octet-stream")


@app.post("/api/speedtest/upload")
async def speedtest_upload(request: Request):
    """Receive data for upload speed test."""
    body = await request.body()
    return {"received": len(body)}


@app.get("/api/client-script")
async def get_client_script(request: Request):
    """Serve the Python test client with server URL pre-configured."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    script_path = os.path.join(static_dir, "network_test.py")
    
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Client script not found")
    
    with open(script_path, "r") as f:
        script_content = f.read()
    
    # Replace placeholder with actual server URL
    host = request.headers.get("host", "localhost:8000")
    protocol = "https" if request.url.scheme == "https" else "http"
    server_url = f"{protocol}://{host}"
    
    script_content = script_content.replace('DEFAULT_SERVER = "{{SERVER_URL}}"', f'DEFAULT_SERVER = "{server_url}"')
    
    return Response(
        content=script_content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=network_test.py"}
    )


@app.get("/api/client-script/ps1")
async def get_powershell_script(request: Request):
    """Serve the PowerShell test client with server URL pre-configured."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    script_path = os.path.join(static_dir, "network_test.ps1")
    
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="PowerShell script not found")
    
    with open(script_path, "r") as f:
        script_content = f.read()
    
    # Replace placeholder with actual server URL
    host = request.headers.get("host", "localhost:8000")
    protocol = "https" if request.url.scheme == "https" else "http"
    server_url = f"{protocol}://{host}"
    
    script_content = script_content.replace('{{SERVER_URL}}', server_url)
    
    return Response(
        content=script_content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=network_test.ps1"}
    )


@app.get("/api/client-script/sh")
async def get_bash_script(request: Request):
    """Serve the Bash test client with server URL pre-configured."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    script_path = os.path.join(static_dir, "network_test.sh")
    
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Bash script not found")
    
    with open(script_path, "r") as f:
        script_content = f.read()
    
    # Replace placeholder with actual server URL
    host = request.headers.get("host", "localhost:8000")
    protocol = "https" if request.url.scheme == "https" else "http"
    server_url = f"{protocol}://{host}"
    
    script_content = script_content.replace('{{SERVER_URL}}', server_url)
    
    return Response(
        content=script_content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=network_test.sh"}
    )


@app.post("/api/speedtest/result")
async def speedtest_save_result(
    request: Request,
    db: Session = Depends(get_db)
):
    """Save speed test result from customer portal."""
    data = await request.json()
    client_ip = get_client_ip(request)
    
    # Check for token
    token_str = data.get("token")
    customer_id = None
    
    if token_str:
        token = validate_customer_token(db, token_str)
        if token:
            customer_id = token.customer_id
    
    test_result = TestResult(
        test_type="speedtest_customer",
        customer_id=customer_id,
        client_ip=client_ip,
        config=json.dumps({
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "token_used": bool(token_str)
        }),
        result=json.dumps(data),
        status="completed",
        completed_at=datetime.utcnow()
    )
    
    db.add(test_result)
    db.commit()
    db.refresh(test_result)
    
    return {"id": test_result.id, "status": "saved"}


# ============== Diagnostic Test Endpoints ==============

@app.post("/api/tests")
async def create_test(
    test_request: TestRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user = Depends(get_optional_user)
):
    """Create and run a diagnostic test."""
    config = get_config()
    
    # Check if feature is enabled
    feature_map = {
        TestType.SPEEDTEST: config.features.speedtest,
        TestType.TRACEROUTE: config.features.traceroute,
        TestType.MTR: config.features.mtr,
        TestType.DNS: config.features.dns,
        TestType.TCP_CHECK: config.features.tcp_check,
        TestType.SSL_CHECK: config.features.ssl_check,
        TestType.IPERF: config.features.iperf,
        TestType.PACKET_CAPTURE: config.features.packet_capture,
        TestType.CONTINUOUS_PING: config.features.continuous_ping,
    }
    
    if not feature_map.get(test_request.test_type, False):
        raise HTTPException(status_code=400, detail=f"Feature {test_request.test_type} is disabled")
    
    # Create test record
    test_result = TestResult(
        test_type=test_request.test_type.value,
        config=json.dumps(test_request.config),
        status="running"
    )
    db.add(test_result)
    db.commit()
    db.refresh(test_result)
    
    # Run test in background
    background_tasks.add_task(
        execute_test,
        test_result.id,
        test_request.test_type.value,
        test_request.config
    )
    
    return {"id": test_result.id, "status": "running"}


def execute_test(test_id: int, test_type: str, config: dict):
    """Execute a diagnostic test."""
    db = next(get_db())
    test_result = db.query(TestResult).filter(TestResult.id == test_id).first()
    
    if not test_result:
        db.close()
        return
    
    try:
        # Select runner based on test type
        runners = {
            "speedtest": speedtest_runner,
            "traceroute": traceroute_runner,
            "mtr": mtr_runner,
            "dns": dns_runner,
            "tcp_check": tcp_runner,
            "ssl_check": ssl_runner,
            "iperf": iperf_runner,
            "packet_capture": capture_runner,
        }
        
        runner = runners.get(test_type)
        if not runner:
            raise Exception(f"Unknown test type: {test_type}")
        
        # Special handling for DNS
        if test_type == "dns":
            lookup_type = config.get("lookup_type", "lookup")
            if lookup_type == "reverse":
                result = runner.reverse_lookup(config)
            elif lookup_type == "propagation":
                result = runner.propagation_check(config)
            else:
                result = runner.lookup(config)
        else:
            result = runner.run(config)
        
        test_result.status = "completed"
        test_result.result = json.dumps(result)
        test_result.completed_at = datetime.utcnow()
        
    except Exception as e:
        test_result.status = "failed"
        test_result.result = json.dumps({"error": str(e)})
        test_result.completed_at = datetime.utcnow()
    
    db.commit()
    db.close()


@app.get("/api/tests")
async def list_tests(
    limit: int = 50,
    test_type: str = None,
    db: Session = Depends(get_db)
):
    """List recent tests."""
    query = db.query(TestResult).order_by(TestResult.created_at.desc())
    
    if test_type:
        query = query.filter(TestResult.test_type == test_type)
    
    tests = query.limit(limit).all()
    
    return [
        {
            "id": t.id,
            "test_type": t.test_type,
            "customer_id": t.customer_id,
            "status": t.status,
            "created_at": t.created_at.isoformat(),
            "completed_at": t.completed_at.isoformat() if t.completed_at else None
        }
        for t in tests
    ]


@app.get("/api/tests/{test_id}")
async def get_test(test_id: int, db: Session = Depends(get_db)):
    """Get test details."""
    test = db.query(TestResult).filter(TestResult.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    return {
        "id": test.id,
        "test_type": test.test_type,
        "customer_id": test.customer_id,
        "client_ip": test.client_ip,
        "config": json.loads(test.config) if test.config else None,
        "result": json.loads(test.result) if test.result else None,
        "status": test.status,
        "created_at": test.created_at.isoformat(),
        "completed_at": test.completed_at.isoformat() if test.completed_at else None
    }


# ============== Continuous Ping Endpoints ==============

@app.post("/api/ping/start")
async def start_ping(config: dict, user = Depends(get_optional_user)):
    """Start a continuous ping session."""
    return ping_runner.start(config)


@app.get("/api/ping/{session_id}")
async def get_ping_status(session_id: int):
    """Get continuous ping session status."""
    return ping_runner.get_status(session_id)


@app.post("/api/ping/{session_id}/stop")
async def stop_ping(session_id: int):
    """Stop a continuous ping session."""
    return ping_runner.stop(session_id)


@app.get("/api/ping")
async def list_ping_sessions():
    """List all ping sessions."""
    return ping_runner.get_all_sessions()


# ============== Utility Endpoints ==============

@app.get("/api/node/info")
async def get_node_info():
    """Get node information."""
    config = get_config()
    return {
        "node_id": config.node_id,
        "node_name": config.node_name,
        "location": config.location,
        "features": config.features.model_dump(),
        "auth_required": config.require_auth
    }


# ============== Static Files ==============

@app.get("/speedtest", response_class=HTMLResponse)
async def speedtest_page(token: str = None):
    """Serve customer speed test page."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    speedtest_path = os.path.join(static_dir, "speedtest.html")
    
    if os.path.exists(speedtest_path):
        with open(speedtest_path, "r") as f:
            return HTMLResponse(content=f.read())
    
    return HTMLResponse(content="<h1>Speed Test page not found</h1>", status_code=404)


# Mount static files last
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
