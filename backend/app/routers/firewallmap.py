"""Firewall Attack Map API routes - Live visualization of firewall blocked traffic."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
import structlog

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service

router = APIRouter()
logger = structlog.get_logger()

# Firewall index pattern
FIREWALL_INDEX = ".ds-filebeat-*"

# Firewall logs are 1 hour behind actual time
FIREWALL_TIMEZONE_OFFSET_HOURS = 1

# Internal/infrastructure IPs to exclude from external attack views
# Keep these only visible in "internal hosts" section
EXCLUDED_INFRA_IPS = {"193.246.121.231", "193.246.121.232", "193.246.121.233"}
INTERNAL_IP_PREFIXES = [
    "192.168.", "10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
]

def get_ip_exclusion_filters():
    """Get standard IP exclusion filters for firewall queries."""
    filters = [
        {"prefix": {"fw.src_ip": "192.168."}},
        {"prefix": {"fw.src_ip": "10."}},
        {"prefix": {"fw.src_ip": "172.16."}},
        {"prefix": {"fw.src_ip": "172.17."}},
        {"prefix": {"fw.src_ip": "172.18."}},
        {"prefix": {"fw.src_ip": "127."}},
    ]
    # Add specific infrastructure IPs
    for ip in EXCLUDED_INFRA_IPS:
        filters.append({"term": {"fw.src_ip": ip}})
    return filters

# Lugano target coordinates (Switzerland)
TARGET_LAT = 46.0037
TARGET_LON = 8.9511

# Action colors
ACTION_COLORS = {
    "block": "#ff3366",
    "pass": "#39ff14",
    "reject": "#ff6600",
}


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private or excluded infrastructure."""
    if not ip:
        return True
    if ip in EXCLUDED_INFRA_IPS:
        return True
    for prefix in INTERNAL_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def get_firewall_time_query(seconds: int) -> dict:
    """Get time range query adjusted for firewall's 1-hour offset."""
    now = datetime.utcnow()
    offset = timedelta(hours=FIREWALL_TIMEZONE_OFFSET_HOURS)
    
    # Shift the window back by 1 hour to compensate
    since = now - timedelta(seconds=seconds) - offset
    until = now - offset
    
    return {
        "range": {
            "@timestamp": {
                "gte": since.isoformat() + "Z",
                "lte": until.isoformat() + "Z"
            }
        }
    }


def extract_firewall_event(source: dict) -> dict:
    """Extract event data from firewall log."""
    result = {
        "src_ip": None,
        "src_lat": None,
        "src_lon": None,
        "src_country": None,
        "dst_port": None,
        "action": None,
        "interface": None,
        "protocol": None,
    }
    
    # Firewall fields
    fw = source.get("fw", {})
    result["src_ip"] = fw.get("src_ip")
    result["dst_port"] = fw.get("dst_port")
    result["action"] = fw.get("action", "block")
    result["interface"] = fw.get("interface")
    result["protocol"] = fw.get("proto")
    
    # Geo data
    source_data = source.get("source", {})
    geo = source_data.get("geo", {})
    location = geo.get("location", {})
    result["src_lat"] = location.get("lat")
    result["src_lon"] = location.get("lon")
    result["src_country"] = geo.get("country_name")
    
    return result


class FirewallMapManager:
    """Manager for firewall map WebSocket connections."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.seen_event_ids: Set[str] = set()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def send_stats(self, websocket: WebSocket, stats: dict):
        try:
            await websocket.send_json({"type": "stats", **stats})
        except Exception:
            pass


firewall_map_manager = FirewallMapManager()


async def poll_firewall_events(poll_seconds: int, seen_ids: Set[str]) -> List[dict]:
    """Poll Elasticsearch for new firewall events."""
    es = get_es_service()
    if not es:
        return []
    
    events = []
    time_query = get_firewall_time_query(poll_seconds)
    
    try:
        # Query both blocked (in) and passed (out to honeypots) traffic
        result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [time_query],
                    "should": [
                        # Blocked: incoming traffic that was blocked
                        {"bool": {"must": [
                            {"term": {"fw.dir": "in"}},
                            {"term": {"fw.action": "block"}}
                        ]}},
                        # Passed: outgoing to honeypots
                        {"bool": {"must": [
                            {"term": {"fw.dir": "out"}},
                            {"term": {"fw.action": "pass"}}
                        ]}}
                    ],
                    "minimum_should_match": 1,
                    "must_not": get_ip_exclusion_filters()
                }
            },
            size=100,
            sort=[{"@timestamp": "desc"}]
        )
        
        for hit in result.get("hits", {}).get("hits", []):
            event_id = hit["_id"]
            
            if event_id in seen_ids:
                continue
            
            seen_ids.add(event_id)
            
            source = hit["_source"]
            data = extract_firewall_event(source)
            
            if is_internal_ip(data["src_ip"]):
                continue
            
            if not data["src_lat"] or not data["src_lon"]:
                continue
            
            events.append({
                "id": event_id,
                "timestamp": source.get("@timestamp", ""),
                "src_ip": data["src_ip"] or "unknown",
                "src_lat": data["src_lat"],
                "src_lon": data["src_lon"],
                "src_country": data["src_country"],
                "dst_lat": TARGET_LAT,
                "dst_lon": TARGET_LON,
                "port": data["dst_port"],
                "action": data["action"],
                "interface": data["interface"],
                "protocol": data["protocol"],
            })
    except Exception as e:
        logger.debug("firewallmap_poll_error", error=str(e))
    
    return events


async def get_firewall_stats() -> dict:
    """Get current firewall map statistics.
    
    Blocked: incoming traffic (fw.dir=in) that was blocked (fw.action=block)
    Passed: outgoing traffic (fw.dir=out) that was passed to honeypots (fw.action=pass)
    Both exclude internal source IPs.
    """
    es = get_es_service()
    if not es:
        return {"total_events": 0, "blocked": 0, "passed": 0, "countries": 0, "unique_ports": 0}
    
    time_query = get_firewall_time_query(86400)  # Last 24 hours for better visibility
    ip_filters = get_ip_exclusion_filters()
    
    try:
        # Query blocked traffic (incoming that was blocked)
        blocked_result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [
                        time_query,
                        {"term": {"fw.dir": "in"}},
                        {"term": {"fw.action": "block"}}
                    ],
                    "must_not": ip_filters
                }
            },
            size=0,
            aggs={
                "countries": {"terms": {"field": "source.geo.country_name", "size": 100}},
                "unique_ports": {"cardinality": {"field": "fw.dst_port"}},
                "unique_ips": {"cardinality": {"field": "fw.src_ip"}},
            }
        )
        
        # Query passed traffic (outgoing to honeypots)
        passed_result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [
                        time_query,
                        {"term": {"fw.dir": "out"}},
                        {"term": {"fw.action": "pass"}}
                    ],
                    "must_not": ip_filters
                }
            },
            size=0,
            aggs={
                "countries": {"terms": {"field": "source.geo.country_name", "size": 100}},
                "unique_ips": {"cardinality": {"field": "fw.src_ip"}},
            }
        )
        
        blocked_count = blocked_result.get("hits", {}).get("total", {}).get("value", 0)
        passed_count = passed_result.get("hits", {}).get("total", {}).get("value", 0)
        
        blocked_aggs = blocked_result.get("aggregations", {})
        passed_aggs = passed_result.get("aggregations", {})
        
        # Combine unique countries from both
        blocked_countries = set(b["key"] for b in blocked_aggs.get("countries", {}).get("buckets", []))
        passed_countries = set(b["key"] for b in passed_aggs.get("countries", {}).get("buckets", []))
        all_countries = blocked_countries | passed_countries
        
        return {
            "total_events": blocked_count + passed_count,
            "blocked": blocked_count,
            "passed": passed_count,
            "countries": len(all_countries),
            "unique_ports": blocked_aggs.get("unique_ports", {}).get("value", 0),
            "unique_ips": blocked_aggs.get("unique_ips", {}).get("value", 0) + passed_aggs.get("unique_ips", {}).get("value", 0),
        }
    except Exception as e:
        logger.error("firewallmap_stats_error", error=str(e))
        return {"total_events": 0, "blocked": 0, "passed": 0, "countries": 0, "unique_ports": 0, "unique_ips": 0}


@router.websocket("/ws")
async def firewallmap_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time firewall map updates."""
    await firewall_map_manager.connect(websocket)
    
    connection_seen_ids: Set[str] = set()
    
    try:
        # Send initial stats
        stats = await get_firewall_stats()
        await firewall_map_manager.send_stats(websocket, stats)
        
        # Send recent events (last 60 seconds due to time offset)
        initial_events = await poll_firewall_events(60, connection_seen_ids)
        for event in initial_events[:30]:
            try:
                await websocket.send_json({"type": "attack", "event": event})
                await asyncio.sleep(0.01)
            except Exception:
                break
        
        # Polling loop
        poll_count = 0
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=0.5)
                
                if data.get("type") == "get_stats":
                    stats = await get_firewall_stats()
                    await firewall_map_manager.send_stats(websocket, stats)
                    
            except asyncio.TimeoutError:
                # Poll for new events (last 5 seconds + offset buffer)
                events = await poll_firewall_events(10, connection_seen_ids)
                for event in events:
                    try:
                        await websocket.send_json({"type": "attack", "event": event})
                    except Exception:
                        break
                
                # Cleanup old seen IDs
                if len(connection_seen_ids) > 2000:
                    connection_seen_ids.clear()
                
                # Update stats every 20 polls (10 seconds)
                poll_count += 1
                if poll_count >= 20:
                    poll_count = 0
                    stats = await get_firewall_stats()
                    await firewall_map_manager.send_stats(websocket, stats)
                    
    except WebSocketDisconnect:
        firewall_map_manager.disconnect(websocket)
    except Exception as e:
        logger.error("firewallmap_ws_error", error=str(e))
        firewall_map_manager.disconnect(websocket)


@router.get("/historical")
async def get_historical_firewall_events(
    limit: int = Query(default=100, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get historical firewall events from the last 24 hours for initial map population."""
    es = get_es_service()
    events = []
    
    time_query = get_firewall_time_query(86400)  # Last 24 hours
    
    try:
        result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [time_query],
                    "should": [
                        {"bool": {"must": [
                            {"term": {"fw.dir": "in"}},
                            {"term": {"fw.action": "block"}}
                        ]}},
                        {"bool": {"must": [
                            {"term": {"fw.dir": "out"}},
                            {"term": {"fw.action": "pass"}}
                        ]}}
                    ],
                    "minimum_should_match": 1,
                    "must_not": get_ip_exclusion_filters()
                }
            },
            size=limit,
            sort=[{"@timestamp": "desc"}]
        )
        
        for hit in result.get("hits", {}).get("hits", []):
            source = hit["_source"]
            data = extract_firewall_event(source)
            
            if is_internal_ip(data["src_ip"]):
                continue
            
            if not data["src_lat"] or not data["src_lon"]:
                continue
            
            events.append({
                "id": hit["_id"],
                "timestamp": source.get("@timestamp", ""),
                "src_ip": data["src_ip"] or "unknown",
                "src_lat": data["src_lat"],
                "src_lon": data["src_lon"],
                "src_country": data["src_country"],
                "dst_lat": TARGET_LAT,
                "dst_lon": TARGET_LON,
                "port": data["dst_port"],
                "action": data["action"],
                "interface": data["interface"],
                "protocol": data["protocol"],
            })
    except Exception as e:
        logger.error("firewallmap_historical_error", error=str(e))
    
    return events[:limit]


@router.get("/recent")
async def get_recent_firewall_events(
    limit: int = Query(default=50, ge=1, le=200),
    seconds: int = Query(default=30, ge=5, le=3600),
    _: str = Depends(get_current_user)
):
    """Get recent firewall events for the map."""
    es = get_es_service()
    events = []
    
    time_query = get_firewall_time_query(seconds)
    
    try:
        # Query both blocked (in) and passed (out to honeypots) traffic
        result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [time_query],
                    "should": [
                        # Blocked: incoming traffic that was blocked
                        {"bool": {"must": [
                            {"term": {"fw.dir": "in"}},
                            {"term": {"fw.action": "block"}}
                        ]}},
                        # Passed: outgoing to honeypots
                        {"bool": {"must": [
                            {"term": {"fw.dir": "out"}},
                            {"term": {"fw.action": "pass"}}
                        ]}}
                    ],
                    "minimum_should_match": 1,
                    "must_not": get_ip_exclusion_filters()
                }
            },
            size=limit,
            sort=[{"@timestamp": "desc"}]
        )
        
        for hit in result.get("hits", {}).get("hits", []):
            source = hit["_source"]
            data = extract_firewall_event(source)
            
            if is_internal_ip(data["src_ip"]):
                continue
            
            if not data["src_lat"] or not data["src_lon"]:
                continue
            
            events.append({
                "id": hit["_id"],
                "timestamp": source.get("@timestamp", ""),
                "src_ip": data["src_ip"] or "unknown",
                "src_lat": data["src_lat"],
                "src_lon": data["src_lon"],
                "src_country": data["src_country"],
                "dst_lat": TARGET_LAT,
                "dst_lon": TARGET_LON,
                "port": data["dst_port"],
                "action": data["action"],
                "interface": data["interface"],
                "protocol": data["protocol"],
            })
    except Exception as e:
        logger.error("firewallmap_recent_error", error=str(e))
    
    return events[:limit]


@router.get("/stats")
async def get_firewallmap_stats(_: str = Depends(get_current_user)):
    """Get current firewall map statistics."""
    return await get_firewall_stats()


@router.get("/top-ports")
async def get_top_ports(
    limit: int = Query(default=10, ge=1, le=50),
    _: str = Depends(get_current_user)
):
    """Get top targeted ports."""
    es = get_es_service()
    
    time_query = get_firewall_time_query(3600)
    
    try:
        result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [time_query, {"term": {"fw.dir": "in"}}],
                    "must_not": get_ip_exclusion_filters()
                }
            },
            size=0,
            aggs={
                "top_ports": {
                    "terms": {"field": "fw.dst_port", "size": limit},
                    "aggs": {
                        "blocked": {"filter": {"term": {"fw.action": "block"}}},
                        "countries": {"cardinality": {"field": "source.geo.country_name"}}
                    }
                }
            }
        )
        
        ports = []
        for bucket in result.get("aggregations", {}).get("top_ports", {}).get("buckets", []):
            ports.append({
                "port": bucket["key"],
                "count": bucket["doc_count"],
                "blocked": bucket.get("blocked", {}).get("doc_count", 0),
                "countries": bucket.get("countries", {}).get("value", 0),
            })
        
        return {"ports": ports}
    except Exception as e:
        logger.error("firewallmap_ports_error", error=str(e))
        return {"ports": []}


@router.get("/top-countries")
async def get_top_countries(
    limit: int = Query(default=10, ge=1, le=50),
    _: str = Depends(get_current_user)
):
    """Get top source countries for firewall events."""
    es = get_es_service()
    
    time_query = get_firewall_time_query(86400)  # Last 24 hours
    
    try:
        result = await es.search(
            index=FIREWALL_INDEX,
            query={
                "bool": {
                    "must": [time_query],
                    "must_not": get_ip_exclusion_filters()
                }
            },
            size=0,
            aggs={
                "countries": {
                    "terms": {"field": "source.geo.country_name", "size": limit},
                    "aggs": {
                        "blocked": {"filter": {"term": {"fw.action": "block"}}},
                        "passed": {"filter": {"term": {"fw.action": "pass"}}}
                    }
                }
            }
        )
        
        countries = []
        for bucket in result.get("aggregations", {}).get("countries", {}).get("buckets", []):
            countries.append({
                "country": bucket["key"],
                "count": bucket["doc_count"],
                "blocked": bucket.get("blocked", {}).get("doc_count", 0),
                "passed": bucket.get("passed", {}).get("doc_count", 0),
            })
        
        return {"countries": countries}
    except Exception as e:
        logger.error("firewallmap_countries_error", error=str(e))
        return {"countries": []}
