"""HTTP Speed Test runner."""
import time
import os
import requests
import concurrent.futures
from typing import Optional, List
from dataclasses import dataclass


@dataclass
class SpeedTestResult:
    ping_min: Optional[float] = None
    ping_avg: Optional[float] = None
    ping_max: Optional[float] = None
    ping_jitter: Optional[float] = None
    download_mbps: Optional[float] = None
    download_bytes: int = 0
    upload_mbps: Optional[float] = None
    upload_bytes: int = 0
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    customer_id: Optional[str] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class SpeedTestRunner:
    """HTTP-based speed test similar to speedtest.net."""
    
    def run(self, config: dict) -> dict:
        """Execute speed test to target."""
        mode = config.get("mode", "client")
        
        if mode == "server":
            # Server mode is handled by FastAPI endpoints
            return {"status": "server_mode", "message": "Server endpoints are active"}
        
        return self._run_client_test(config)
    
    def _run_client_test(self, config: dict) -> dict:
        """Test download/upload speed to a remote HTTP endpoint."""
        target_url = config.get("target_url", "").rstrip("/")
        duration = config.get("duration", 10)
        parallel = config.get("parallel", 4)
        
        if not target_url:
            return {"error": "target_url is required"}
        
        result = SpeedTestResult()
        
        # Ping test
        try:
            ping_times = self._test_ping(target_url, count=10)
            if ping_times:
                result.ping_min = round(min(ping_times), 2)
                result.ping_avg = round(sum(ping_times) / len(ping_times), 2)
                result.ping_max = round(max(ping_times), 2)
                result.ping_jitter = round(self._calc_jitter(ping_times), 2) if len(ping_times) > 1 else 0
        except Exception as e:
            result.errors.append(f"Ping failed: {str(e)}")
        
        # Download test
        try:
            dl_mbps, dl_bytes = self._test_download(target_url, duration, parallel)
            result.download_mbps = dl_mbps
            result.download_bytes = dl_bytes
        except Exception as e:
            result.errors.append(f"Download failed: {str(e)}")
        
        # Upload test
        try:
            ul_mbps, ul_bytes = self._test_upload(target_url, duration, parallel)
            result.upload_mbps = ul_mbps
            result.upload_bytes = ul_bytes
        except Exception as e:
            result.errors.append(f"Upload failed: {str(e)}")
        
        return {
            "ping_min": result.ping_min,
            "ping_avg": result.ping_avg,
            "ping_max": result.ping_max,
            "ping_jitter": result.ping_jitter,
            "download_mbps": result.download_mbps,
            "download_bytes": result.download_bytes,
            "upload_mbps": result.upload_mbps,
            "upload_bytes": result.upload_bytes,
            "errors": result.errors
        }
    
    def _test_ping(self, target_url: str, count: int = 10) -> List[float]:
        """Measure latency to target."""
        times = []
        
        for _ in range(count):
            try:
                start = time.time()
                requests.get(f"{target_url}/api/speedtest/ping", timeout=5)
                times.append((time.time() - start) * 1000)
            except:
                pass
        
        return times
    
    def _test_download(self, target_url: str, duration: int, parallel: int) -> tuple:
        """Download test using multiple parallel streams."""
        total_bytes = 0
        start_time = time.time()
        end_time = start_time + duration
        lock = concurrent.futures.thread.threading.Lock()
        
        def download_chunk():
            nonlocal total_bytes
            session = requests.Session()
            local_bytes = 0
            
            while time.time() < end_time:
                try:
                    resp = session.get(
                        f"{target_url}/api/speedtest/download",
                        params={"size": 1048576},  # 1MB chunks
                        timeout=30
                    )
                    local_bytes += len(resp.content)
                except:
                    pass
            
            with lock:
                total_bytes += local_bytes
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = [executor.submit(download_chunk) for _ in range(parallel)]
            concurrent.futures.wait(futures)
        
        elapsed = time.time() - start_time
        mbps = round((total_bytes * 8) / (elapsed * 1000000), 2)
        
        return mbps, total_bytes
    
    def _test_upload(self, target_url: str, duration: int, parallel: int) -> tuple:
        """Upload test using multiple parallel streams."""
        total_bytes = 0
        start_time = time.time()
        end_time = start_time + duration
        lock = concurrent.futures.thread.threading.Lock()
        
        # Pre-generate upload data (256KB chunks)
        upload_data = os.urandom(262144)
        
        def upload_chunk():
            nonlocal total_bytes
            session = requests.Session()
            local_bytes = 0
            
            while time.time() < end_time:
                try:
                    resp = session.post(
                        f"{target_url}/api/speedtest/upload",
                        data=upload_data,
                        headers={"Content-Type": "application/octet-stream"},
                        timeout=30
                    )
                    if resp.status_code == 200:
                        local_bytes += len(upload_data)
                except:
                    pass
            
            with lock:
                total_bytes += local_bytes
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = [executor.submit(upload_chunk) for _ in range(parallel)]
            concurrent.futures.wait(futures)
        
        elapsed = time.time() - start_time
        mbps = round((total_bytes * 8) / (elapsed * 1000000), 2)
        
        return mbps, total_bytes
    
    def _calc_jitter(self, times: List[float]) -> float:
        """Calculate jitter from latency measurements."""
        if len(times) < 2:
            return 0.0
        diffs = [abs(times[i] - times[i-1]) for i in range(1, len(times))]
        return sum(diffs) / len(diffs)
