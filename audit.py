#!/usr/bin/env python3
import logging
import sys
from typing import Any, Dict, List, Optional
import requests
from requests.exceptions import ConnectionError, ReadTimeout, RequestException

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("kessel.audit")

class EndpointAuditor:
    def __init__(self, default_timeout: float = 5.0):
        self.timeout = default_timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "KesselFlow-AuditEngine/1.0"
        })

    def audit_target(self, url: str) -> Dict[str, Any]:
        """Audit a single URL endpoint with explicit error trapping."""
        record: Dict[str, Any] = {
            "target": url,
            "status": "UNKNOWN",
            "status_code": None,
            "latency_ms": None,
            "error": None
        }

        try:
            logger.info("Auditing target: %s", url)
            response = self.session.get(url, timeout=self.timeout)
            record["status_code"] = response.status_code
            record["latency_ms"] = round(response.elapsed.total_seconds() * 1000, 2)
            record["status"] = "HEALTHY" if response.ok else "UNHEALTHY"
            logger.info("Target: %s | Code: %d | Latency: %sms", url, response.status_code, record["latency_ms"])

        except ConnectionError as err:
            record["status"] = "CONNECTION_REFUSED"
            record["error"] = str(err)
            logger.error("Connection failed for %s: %s", url, err)

        except ReadTimeout as err:
            record["status"] = "TIMEOUT"
            record["error"] = str(err)
            logger.error("Read timeout (%ss) on %s", self.timeout, url)

        except RequestException as err:
            record["status"] = "REQUEST_FAILED"
            record["error"] = str(err)
            logger.error("General failure on %s: %s", url, err)

        return record

    def run_batch(self, targets: List[str]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for target in targets:
            results.append(self.audit_target(target))
        return results

if __name__ == "__main__":
    endpoints = [
        "http://127.0.0.1:8000/health",
        "https://httpbin.org/status/200"
    ]
    auditor = EndpointAuditor(default_timeout=3.0)
    audit_results = auditor.run_batch(endpoints)
