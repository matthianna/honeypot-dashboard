"""Attack Map API routes with WebSocket support."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
import structlog

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service
from app.models.schemas import AttackEvent, AttackMapStats

router = APIRouter()
logger = structlog.get_logger()

# Internal IPs to exclude
INTERNAL_IPS = {"193.246.121.231", "193.246.121.232", "193.246.121.233"}

# Honeypot index patterns (no firewall - it has its own dedicated map)
INDEX_PATTERNS = {
    "cowrie": ".ds-cowrie-*",
    "dionaea": "dionaea-*",
    "galah": ".ds-galah-*",
    "rdpy": ".ds-rdpy-*",
    "heralding": ".ds-heralding-*",
}

# Internal/private IPs to filter
INTERNAL_IP_PREFIXES = ["192.168.", "10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]

DEFAULT_PORTS = {
    "cowrie": 22,
    "dionaea": None,
    "galah": 80,
    "rdpy": 3389,
    "heralding": None,
}


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private and should be excluded."""
    if not ip:
        return True
    if ip in INTERNAL_IPS:
        return True
    for prefix in INTERNAL_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def extract_event_data(source: dict, honeypot: str) -> dict:
    """Extract event data based on honeypot type with correct field mappings."""
    result = {
        "src_ip": None,
        "src_lat": None,
        "src_lon": None,
        "src_country": None,
        "dst_port": None,
    }
    
    if honeypot == "cowrie":
        cowrie = source.get("cowrie", {})
        result["src_ip"] = cowrie.get("src_ip")
        geo = cowrie.get("geo", {})
        location = geo.get("location", {})
        result["src_lat"] = location.get("lat")
        result["src_lon"] = location.get("lon")
        result["src_country"] = geo.get("country_name")
        json_data = source.get("json", {})
        result["dst_port"] = json_data.get("dst_port", 22)
    else:
        # galah, dionaea, rdpy, heralding all use source.* fields
        source_data = source.get("source", {})
        result["src_ip"] = source_data.get("ip")
        geo = source_data.get("geo", {})
        location = geo.get("location", {})
        result["src_lat"] = location.get("lat")
        result["src_lon"] = location.get("lon")
        result["src_country"] = geo.get("country_name")
        result["dst_port"] = source.get("destination", {}).get("port")
    
    return result


class AttackMapManager:
    """Manager for attack map WebSocket connections."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.seen_event_ids: Set[str] = set()  # Track seen events to avoid duplicates
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast_event(self, event: dict):
        """Broadcast a single event to all connected clients."""
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_json({
                    "type": "attack",
                    "event": event
                })
            except Exception:
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)
    
    async def send_stats(self, websocket: WebSocket, stats: dict):
        """Send stats to a specific client."""
        try:
            await websocket.send_json({
                "type": "stats",
                **stats
            })
        except Exception:
            pass
    
    def is_new_event(self, event_id: str) -> bool:
        """Check if event is new (not seen before)."""
        if event_id in self.seen_event_ids:
            return False
        self.seen_event_ids.add(event_id)
        # Keep only last 1000 event IDs
        if len(self.seen_event_ids) > 1000:
            self.seen_event_ids = set(list(self.seen_event_ids)[-500:])
        return True


attack_map_manager = AttackMapManager()


async def poll_new_events(poll_seconds: int = 10) -> List[dict]:
    """Poll Elasticsearch for new events from all honeypots."""
    es = get_es_service()
    if not es:
        return []
    
    events = []
    now = datetime.utcnow()
    poll_start = now - timedelta(seconds=poll_seconds)
    
    for honeypot, index_pattern in INDEX_PATTERNS.items():
        try:
            # Build query - for dionaea, also filter for source.ip existence
            must_clauses = [{
                "range": {
                    "@timestamp": {
                        "gte": poll_start.isoformat() + "Z",
                        "lte": now.isoformat() + "Z"
                    }
                }
            }]
            
            # Dionaea: only events with source.ip (real connections)
            if honeypot == "dionaea":
                must_clauses.append({"exists": {"field": "source.ip"}})
            
            result = await es.search(
                index=index_pattern,
                query={"bool": {"must": must_clauses}},
                size=50,
                sort=[{"@timestamp": "desc"}]
            )
            
            for hit in result.get("hits", {}).get("hits", []):
                event_id = hit["_id"]
                
                # Skip already seen events
                if not attack_map_manager.is_new_event(event_id):
                    continue
                
                source = hit["_source"]
                data = extract_event_data(source, honeypot)
                
                # Skip internal IPs
                if is_internal_ip(data["src_ip"]):
                    continue
                
                # Skip events without valid coordinates
                if not data["src_lat"] or not data["src_lon"]:
                    continue
                
                events.append({
                    "id": event_id,
                    "timestamp": source.get("@timestamp", ""),
                    "honeypot": honeypot,
                    "src_ip": data["src_ip"] or "unknown",
                    "src_lat": data["src_lat"],
                    "src_lon": data["src_lon"],
                    "src_country": data["src_country"],
                    "dst_lat": 47.3769,  # Zurich
                    "dst_lon": 8.5417,
                    "port": data["dst_port"] or DEFAULT_PORTS.get(honeypot)
                })
        except Exception as e:
            logger.debug("attackmap_poll_error", honeypot=honeypot, error=str(e))
    
    return events


async def get_current_stats() -> dict:
    """Get current attack map statistics."""
    es = get_es_service()
    if not es:
        return {"total_attacks": 0, "unique_ips": 0, "countries": 0}
    
    total_attacks = 0
    countries = set()
    
    for honeypot, index_pattern in INDEX_PATTERNS.items():
        try:
            # Determine IP and country fields (use .keyword for text fields)
            if honeypot == "cowrie":
                ip_field = "cowrie.src_ip"
                country_field = "cowrie.geo.country_name"
            else:
                ip_field = "source.ip"
                country_field = "source.geo.country_name.keyword"
            
            result = await es.search(
                index=index_pattern,
                query=es._get_time_range_query("1h"),
                size=0,
                aggs={
                    "total": {"value_count": {"field": "@timestamp"}},
                    "countries": {"terms": {"field": country_field, "size": 100}}
                }
            )
            
            aggs = result.get("aggregations", {})
            total_attacks += aggs.get("total", {}).get("value", 0)
            
            for bucket in aggs.get("countries", {}).get("buckets", []):
                if bucket["key"]:
                    countries.add(bucket["key"])
        except Exception:
            pass
    
    return {
        "total_attacks": total_attacks,
        "unique_ips": total_attacks // 3,  # Rough estimate
        "countries": len(countries)
    }


@router.websocket("/ws")
async def attackmap_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time attack map updates."""
    await attack_map_manager.connect(websocket)
    
    try:
        # Send initial stats
        stats = await get_current_stats()
        await attack_map_manager.send_stats(websocket, stats)
        
        # Send recent events immediately
        recent = await poll_new_events(60)  # Last 60 seconds
        for event in recent[:20]:  # Limit initial burst
            try:
                await websocket.send_json({"type": "attack", "event": event})
                await asyncio.sleep(0.05)  # Small delay for smooth animation
            except Exception:
                break
        
        # Polling loop - poll every 2 seconds
        poll_count = 0
        while True:
            try:
                # Check for incoming messages with short timeout
                data = await asyncio.wait_for(websocket.receive_json(), timeout=2.0)
                
                if data.get("type") == "get_stats":
                    stats = await get_current_stats()
                    await attack_map_manager.send_stats(websocket, stats)
                    
            except asyncio.TimeoutError:
                # Poll for new events
                events = await poll_new_events(5)
                for event in events:
                    await attack_map_manager.broadcast_event(event)
                
                # Update stats every 5 polls (10 seconds)
                poll_count += 1
                if poll_count >= 5:
                    poll_count = 0
                    stats = await get_current_stats()
                    await attack_map_manager.send_stats(websocket, stats)
                    
    except WebSocketDisconnect:
        attack_map_manager.disconnect(websocket)
    except Exception as e:
        logger.error("attackmap_ws_error", error=str(e))
        attack_map_manager.disconnect(websocket)


@router.get("/recent")
async def get_recent_attacks(
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(get_current_user)
):
    """Get recent attacks for initial map population."""
    es = get_es_service()
    events = []
    
    per_index_limit = (limit // len(INDEX_PATTERNS)) + 5
    
    for honeypot, index_pattern in INDEX_PATTERNS.items():
        try:
            result = await es.search(
                index=index_pattern,
                query=es._get_time_range_query("1h"),
                size=per_index_limit,
                sort=[{"@timestamp": "desc"}]
            )
            
            for hit in result.get("hits", {}).get("hits", []):
                source = hit["_source"]
                data = extract_event_data(source, honeypot)
                
                # Skip internal IPs
                if is_internal_ip(data["src_ip"]):
                    continue
                
                # Skip events without valid geo data
                if not data["src_lat"] or not data["src_lon"]:
                    continue
                
                events.append({
                    "id": hit["_id"],
                    "timestamp": source.get("@timestamp", ""),
                    "honeypot": honeypot,
                    "src_ip": data["src_ip"] or "unknown",
                    "src_lat": data["src_lat"],
                    "src_lon": data["src_lon"],
                    "src_country": data["src_country"],
                    "dst_lat": 47.3769,
                    "dst_lon": 8.5417,
                    "port": data["dst_port"] or DEFAULT_PORTS.get(honeypot)
                })
        except Exception as e:
            logger.debug("attackmap_recent_error", honeypot=honeypot, error=str(e))
    
    # Sort by timestamp and limit
    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return events[:limit]


@router.get("/stats")
async def get_attackmap_stats(_: str = Depends(get_current_user)):
    """Get current attack map statistics."""
    return await get_current_stats()
