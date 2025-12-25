"""RDPY RDP honeypot API routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service
from app.models.schemas import (
    StatsResponse,
    TimelineResponse,
    TimelinePoint,
    GeoDistributionResponse,
    GeoPoint,
    TopAttackersResponse,
    TopAttacker,
    RDPYSession,
    RDPYCredential,
)

router = APIRouter()
INDEX = ".ds-rdpy-*"


@router.get("/stats", response_model=StatsResponse)
async def get_rdpy_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDPY honeypot statistics."""
    es = get_es_service()
    
    total_events = await es.get_total_events(INDEX, time_range)
    unique_ips = await es.get_unique_ips(INDEX, time_range)
    
    return StatsResponse(
        total_events=total_events,
        unique_ips=unique_ips,
        time_range=time_range
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_rdpy_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDPY event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    timeline = await es.get_timeline(INDEX, time_range, interval)
    
    return TimelineResponse(
        data=[TimelinePoint(**point) for point in timeline],
        time_range=time_range
    )


@router.get("/geo", response_model=GeoDistributionResponse)
async def get_rdpy_geo(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDPY geographic distribution."""
    es = get_es_service()
    
    geo_data = await es.get_geo_distribution(INDEX, time_range)
    
    return GeoDistributionResponse(
        data=[GeoPoint(**point) for point in geo_data],
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_rdpy_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top RDPY attackers."""
    es = get_es_service()
    
    top_ips = await es.get_top_source_ips(INDEX, time_range, size=limit)
    
    attackers = [
        TopAttacker(
            ip=ip_data["ip"],
            count=ip_data["count"],
            country=ip_data.get("geo", {}).get("country_name"),
            city=ip_data.get("geo", {}).get("city_name")
        )
        for ip_data in top_ips
    ]
    
    return TopAttackersResponse(data=attackers, time_range=time_range)


@router.get("/sessions", response_model=List[RDPYSession])
async def get_rdpy_sessions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get RDPY sessions."""
    es = get_es_service()
    
    # Get sessions with connection events
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"exists": {"field": "source.ip"}}
                ]
            }
        },
        size=limit,
        sort=[{"@timestamp": "desc"}]
    )
    
    sessions = []
    seen_ips = set()
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        src_ip = source.get("source", {}).get("ip")
        
        # Deduplicate by IP for session view
        if src_ip and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            sessions.append(RDPYSession(
                session_id=hit["_id"],
                src_ip=src_ip,
                username=source.get("user", {}).get("name"),
                domain=source.get("user", {}).get("domain"),
                timestamp=source.get("@timestamp", ""),
                country=source.get("source", {}).get("geo", {}).get("country_name"),
                message=source.get("message")
            ))
    
    return sessions


@router.get("/credentials", response_model=List[RDPYCredential])
async def get_rdpy_credentials(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get most common RDP credential attempts.
    
    RDPY logs credentials in the message field as CSV:
    timestamp,domain:,username:xxx,password:xxx,hostname:xxx
    """
    import re
    es = get_es_service()
    
    # Search for messages containing username/password
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"wildcard": {"message": "*username:*"}}
                ]
            }
        },
        size=500,
        sort=[{"@timestamp": "desc"}]
    )
    
    # Parse credentials from message field
    # Format: timestamp,domain:,username:xxx,password:xxx,hostname:xxx
    cred_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        message = source.get("message", "")
        
        # Parse CSV-like format
        username_match = re.search(r'username:([^,]*)', message)
        password_match = re.search(r'password:([^,]*)', message)
        domain_match = re.search(r'domain:([^,]*)', message)
        
        if username_match:
            username = username_match.group(1).strip()
            password = password_match.group(1).strip() if password_match else ""
            domain = domain_match.group(1).strip() if domain_match else ""
            
            if username:
                key = (username, password, domain)
                cred_counts[key] = cred_counts.get(key, 0) + 1
    
    credentials = [
        RDPYCredential(
            username=key[0],
            password=key[1] if key[1] else None,
            domain=key[2] if key[2] else None,
            count=count
        )
        for key, count in sorted(cred_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return credentials


@router.get("/logs")
async def get_rdpy_logs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    src_ip: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get RDPY logs with filtering options."""
    es = get_es_service()
    
    filters = {}
    if src_ip:
        filters["source.ip"] = src_ip
    
    return await es.get_logs(INDEX, time_range, limit, search, filters)


@router.get("/heatmap")
async def get_rdpy_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly heatmap data for RDPY."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    return {"data": heatmap_data, "time_range": time_range}


@router.get("/connection-patterns")
async def get_rdpy_connection_patterns(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDP connection pattern analysis."""
    es = get_es_service()
    
    # Get connection counts per IP
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_ip": {
                "terms": {"field": "source.ip", "size": 50},
                "aggs": {
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "by_hour": {
                        "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}
                    }
                }
            },
            "by_country": {
                "terms": {"field": "source.geo.country_name.keyword", "size": 20}
            },
            "total_connections": {"value_count": {"field": "@timestamp"}},
            "unique_sources": {"cardinality": {"field": "source.ip"}}
        }
    )
    
    # Analyze connection patterns
    repeat_attackers = []
    for bucket in result.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        ip = bucket["key"]
        count = bucket["doc_count"]
        
        if count >= 2:  # Repeat attacker
            first_seen = bucket.get("first_seen", {}).get("value_as_string")
            last_seen = bucket.get("last_seen", {}).get("value_as_string")
            
            # Calculate intensity (connections per hour active)
            hourly_buckets = bucket.get("by_hour", {}).get("buckets", [])
            active_hours = len([h for h in hourly_buckets if h.get("doc_count", 0) > 0])
            intensity = round(count / max(active_hours, 1), 1)
            
            repeat_attackers.append({
                "ip": ip,
                "connection_count": count,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "active_hours": active_hours,
                "intensity": intensity,  # connections per active hour
            })
    
    # Sort by connection count
    repeat_attackers.sort(key=lambda x: -x["connection_count"])
    
    # Country distribution
    countries = [{"country": b["key"], "count": b["doc_count"]} 
                 for b in result.get("aggregations", {}).get("by_country", {}).get("buckets", [])]
    
    return {
        "time_range": time_range,
        "repeat_attackers": repeat_attackers[:20],
        "countries": countries,
        "summary": {
            "total_connections": result.get("aggregations", {}).get("total_connections", {}).get("value", 0),
            "unique_sources": result.get("aggregations", {}).get("unique_sources", {}).get("value", 0),
            "repeat_attacker_count": len([a for a in repeat_attackers if a["connection_count"] >= 3]),
        }
    }


@router.get("/attack-velocity")
async def get_rdpy_attack_velocity(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDP attack velocity over time."""
    es = get_es_service()
    
    intervals = {"1h": "1m", "24h": "15m", "7d": "1h", "30d": "6h"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "velocity": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": interval},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}}
                }
            },
            "peak_hour": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}
            }
        }
    )
    
    velocity = []
    for bucket in result.get("aggregations", {}).get("velocity", {}).get("buckets", []):
        velocity.append({
            "timestamp": bucket["key_as_string"],
            "connections": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0)
        })
    
    # Find peak hour
    peak_hour_buckets = result.get("aggregations", {}).get("peak_hour", {}).get("buckets", [])
    peak_hour = None
    peak_count = 0
    for bucket in peak_hour_buckets:
        if bucket["doc_count"] > peak_count:
            peak_count = bucket["doc_count"]
            peak_hour = bucket["key_as_string"]
    
    return {
        "time_range": time_range,
        "velocity": velocity[-48:] if len(velocity) > 48 else velocity,
        "peak_hour": peak_hour,
        "peak_connections": peak_count
    }
