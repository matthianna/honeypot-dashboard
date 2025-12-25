"""Heralding multi-protocol honeypot API routes."""

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
    HeraldingCredential,
    HeraldingProtocolStats,
)

router = APIRouter()
INDEX = ".ds-heralding-*"


@router.get("/stats", response_model=StatsResponse)
async def get_heralding_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Heralding honeypot statistics."""
    es = get_es_service()
    
    total_events = await es.get_total_events(INDEX, time_range)
    unique_ips = await es.get_unique_ips(INDEX, time_range)
    
    return StatsResponse(
        total_events=total_events,
        unique_ips=unique_ips,
        time_range=time_range
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_heralding_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Heralding event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    timeline = await es.get_timeline(INDEX, time_range, interval)
    
    return TimelineResponse(
        data=[TimelinePoint(**point) for point in timeline],
        time_range=time_range
    )


@router.get("/geo", response_model=GeoDistributionResponse)
async def get_heralding_geo(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Heralding geographic distribution."""
    es = get_es_service()
    
    geo_data = await es.get_geo_distribution(INDEX, time_range)
    
    return GeoDistributionResponse(
        data=[GeoPoint(**point) for point in geo_data],
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_heralding_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top Heralding attackers."""
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


@router.get("/sessions")
async def get_heralding_sessions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    protocol: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get Heralding session details."""
    es = get_es_service()
    
    must_clauses = [es._get_time_range_query(time_range)]
    
    if protocol:
        must_clauses.append({"term": {"network.protocol": protocol}})
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=limit,
        sort=[{"@timestamp": "desc"}]
    )
    
    sessions = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        
        sessions.append({
            "id": hit["_id"],
            "session_id": source.get("session_id"),
            "timestamp": source.get("@timestamp"),
            "source_ip": source.get("source", {}).get("ip"),
            "source_port": source.get("source", {}).get("port"),
            "destination_port": source.get("destination", {}).get("port"),
            "protocol": source.get("network", {}).get("protocol"),
            "duration": source.get("duration"),
            "auth_attempts": source.get("num_auth_attempts"),
            "geo": {
                "country": source.get("source", {}).get("geo", {}).get("country_name"),
                "city": source.get("source", {}).get("geo", {}).get("city_name"),
            }
        })
    
    return {
        "total": result.get("hits", {}).get("total", {}).get("value", 0),
        "sessions": sessions
    }


@router.get("/credentials", response_model=List[HeraldingCredential])
async def get_heralding_credentials(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    protocol: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get most common credential attempts from auth_attempts array."""
    es = get_es_service()
    
    must_clauses = [
        es._get_time_range_query(time_range),
        {"range": {"num_auth_attempts": {"gt": 0}}}  # Only sessions with auth attempts
    ]
    
    if protocol:
        must_clauses.append({"term": {"network.protocol": protocol}})
    
    # Get raw events with auth attempts
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=500,  # Get more docs to aggregate
        sort=[{"@timestamp": "desc"}]
    )
    
    # Aggregate credentials from auth_attempts array
    cred_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        protocol_name = source.get("network", {}).get("protocol", "unknown")
        auth_attempts = source.get("auth_attempts", [])
        
        for attempt in auth_attempts:
            username = attempt.get("username", "")
            password = attempt.get("password", "")
            
            if username:
                key = (protocol_name, username, password)
                cred_counts[key] = cred_counts.get(key, 0) + 1
    
    credentials = [
        HeraldingCredential(
            protocol=key[0],
            username=key[1],
            password=key[2],
            count=count
        )
        for key, count in sorted(cred_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return credentials


@router.get("/protocols", response_model=List[HeraldingProtocolStats])
async def get_heralding_protocols(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get protocol statistics."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "protocols": {
                "terms": {
                    "field": "network.protocol",
                    "size": 20
                },
                "aggs": {
                    "unique_ips": {
                        "cardinality": {"field": "source.ip"}
                    }
                }
            }
        }
    )
    
    protocols = []
    for bucket in result.get("aggregations", {}).get("protocols", {}).get("buckets", []):
        protocols.append(HeraldingProtocolStats(
            protocol=bucket["key"],
            count=bucket["doc_count"],
            unique_ips=bucket["unique_ips"]["value"]
        ))
    
    return protocols


@router.get("/logs")
async def get_heralding_logs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    protocol: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get Heralding logs with filtering options."""
    es = get_es_service()
    
    filters = {}
    if protocol:
        filters["network.protocol"] = protocol
    if src_ip:
        filters["source.ip"] = src_ip
    
    return await es.get_logs(INDEX, time_range, limit, search, filters)


@router.get("/heatmap")
async def get_heralding_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly heatmap data for Heralding."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    return {"data": heatmap_data, "time_range": time_range}


@router.get("/protocol-analysis")
async def get_heralding_protocol_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get detailed protocol analysis with auth attempts and duration stats."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_protocol": {
                "terms": {"field": "network.protocol", "size": 20},
                "aggs": {
                    "unique_ips": {
                        "cardinality": {"field": "source.ip"}
                    },
                    "unique_sessions": {
                        "cardinality": {"field": "session_id"}
                    },
                    "avg_duration": {
                        "avg": {"field": "duration"}
                    },
                    "max_duration": {
                        "max": {"field": "duration"}
                    },
                    "total_auth_attempts": {
                        "sum": {"field": "num_auth_attempts"}
                    },
                    "avg_auth_attempts": {
                        "avg": {"field": "num_auth_attempts"}
                    },
                    "by_port": {
                        "terms": {"field": "destination.port", "size": 10}
                    },
                    "timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1h" if time_range == "24h" else "6h"
                        }
                    }
                }
            }
        }
    )
    
    protocols = []
    for bucket in result.get("aggregations", {}).get("by_protocol", {}).get("buckets", []):
        protocols.append({
            "protocol": bucket["key"],
            "total_events": bucket["doc_count"],
            "unique_ips": bucket["unique_ips"]["value"],
            "unique_sessions": bucket["unique_sessions"]["value"],
            "avg_duration": round(bucket["avg_duration"]["value"] or 0, 2),
            "max_duration": round(bucket["max_duration"]["value"] or 0, 2),
            "total_auth_attempts": int(bucket["total_auth_attempts"]["value"] or 0),
            "avg_auth_attempts": round(bucket["avg_auth_attempts"]["value"] or 0, 2),
            "ports": [
                {"port": p["key"], "count": p["doc_count"]}
                for p in bucket["by_port"]["buckets"]
            ],
            "timeline": [
                {"timestamp": t["key_as_string"], "count": t["doc_count"]}
                for t in bucket["timeline"]["buckets"]
            ]
        })
    
    return {"protocols": protocols, "time_range": time_range}


@router.get("/session-stats")
async def get_heralding_session_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get session statistics including duration distribution."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "total_sessions": {
                "cardinality": {"field": "session_id"}
            },
            "duration_stats": {
                "stats": {"field": "duration"}
            },
            "duration_percentiles": {
                "percentiles": {
                    "field": "duration",
                    "percents": [50, 75, 90, 95, 99]
                }
            },
            "duration_histogram": {
                "histogram": {
                    "field": "duration",
                    "interval": 5,
                    "min_doc_count": 1
                }
            },
            "auth_attempts_distribution": {
                "terms": {"field": "num_auth_attempts", "size": 20}
            },
            "sessions_with_auth": {
                "filter": {"range": {"num_auth_attempts": {"gt": 0}}}
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    return {
        "time_range": time_range,
        "total_sessions": aggs.get("total_sessions", {}).get("value", 0),
        "sessions_with_auth": aggs.get("sessions_with_auth", {}).get("doc_count", 0),
        "duration_stats": aggs.get("duration_stats", {}),
        "duration_percentiles": aggs.get("duration_percentiles", {}).get("values", {}),
        "duration_histogram": [
            {"range": f"{int(b['key'])}-{int(b['key'])+5}s", "count": b["doc_count"]}
            for b in aggs.get("duration_histogram", {}).get("buckets", [])
        ],
        "auth_attempts_distribution": [
            {"attempts": b["key"], "count": b["doc_count"]}
            for b in aggs.get("auth_attempts_distribution", {}).get("buckets", [])
        ]
    }


@router.get("/protocol-detailed-stats")
async def get_heralding_protocol_detailed_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get detailed per-protocol metrics including success rates and duration."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_protocol": {
                "terms": {"field": "network.protocol", "size": 15},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}},
                    "avg_duration": {"avg": {"field": "duration"}},
                    "total_attempts": {"sum": {"field": "num_auth_attempts"}},
                    "avg_attempts": {"avg": {"field": "num_auth_attempts"}},
                    "by_port": {
                        "terms": {"field": "destination.port", "size": 5}
                    }
                }
            }
        }
    )
    
    protocols = []
    for bucket in result.get("aggregations", {}).get("by_protocol", {}).get("buckets", []):
        ports = [p["key"] for p in bucket.get("by_port", {}).get("buckets", [])]
        protocols.append({
            "protocol": bucket["key"],
            "sessions": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0),
            "avg_duration": round(bucket.get("avg_duration", {}).get("value", 0) or 0, 2),
            "total_auth_attempts": int(bucket.get("total_attempts", {}).get("value", 0) or 0),
            "avg_auth_attempts": round(bucket.get("avg_attempts", {}).get("value", 0) or 0, 1),
            "ports": ports
        })
    
    return {"time_range": time_range, "protocols": protocols}


@router.get("/attempt-intensity")
async def get_heralding_attempt_intensity(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get authentication attempt intensity over time."""
    es = get_es_service()
    
    # Determine interval based on time range
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval
                },
                "aggs": {
                    "total_attempts": {"sum": {"field": "num_auth_attempts"}},
                    "avg_attempts": {"avg": {"field": "num_auth_attempts"}},
                    "unique_ips": {"cardinality": {"field": "source.ip"}}
                }
            }
        }
    )
    
    intensity_data = []
    for bucket in result.get("aggregations", {}).get("over_time", {}).get("buckets", []):
        intensity_data.append({
            "timestamp": bucket["key_as_string"],
            "sessions": bucket["doc_count"],
            "total_attempts": int(bucket.get("total_attempts", {}).get("value", 0) or 0),
            "avg_attempts": round(bucket.get("avg_attempts", {}).get("value", 0) or 0, 1),
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0)
        })
    
    return {"time_range": time_range, "intensity": intensity_data}


@router.get("/session-duration-by-protocol")
async def get_heralding_session_duration_by_protocol(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get session duration statistics broken down by protocol."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_protocol": {
                "terms": {"field": "network.protocol", "size": 10},
                "aggs": {
                    "duration_stats": {
                        "stats": {"field": "duration"}
                    },
                    "percentiles": {
                        "percentiles": {"field": "duration", "percents": [25, 50, 75, 90]}
                    }
                }
            }
        }
    )
    
    protocol_durations = []
    for bucket in result.get("aggregations", {}).get("by_protocol", {}).get("buckets", []):
        stats = bucket.get("duration_stats", {})
        percentiles = bucket.get("percentiles", {}).get("values", {})
        protocol_durations.append({
            "protocol": bucket["key"],
            "sessions": bucket["doc_count"],
            "min": round(stats.get("min", 0) or 0, 2),
            "max": round(stats.get("max", 0) or 0, 2),
            "avg": round(stats.get("avg", 0) or 0, 2),
            "p50": round(percentiles.get("50.0", 0) or 0, 2),
            "p75": round(percentiles.get("75.0", 0) or 0, 2),
            "p90": round(percentiles.get("90.0", 0) or 0, 2),
        })
    
    return {"time_range": time_range, "protocol_durations": protocol_durations}


@router.get("/credential-velocity")
async def get_heralding_credential_velocity(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get credential brute-force velocity - attempts per minute over time."""
    es = get_es_service()
    
    # Use finer granularity for velocity
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "5m" if time_range in ["1h", "24h"] else "1h"
                },
                "aggs": {
                    "total_attempts": {"sum": {"field": "num_auth_attempts"}}
                }
            },
            "overall": {
                "sum": {"field": "num_auth_attempts"}
            }
        }
    )
    
    velocity_data = []
    for bucket in result.get("aggregations", {}).get("over_time", {}).get("buckets", []):
        attempts = int(bucket.get("total_attempts", {}).get("value", 0) or 0)
        # Convert to per-minute rate based on interval
        rate_per_min = attempts / 5 if time_range in ["1h", "24h"] else attempts / 60
        velocity_data.append({
            "timestamp": bucket["key_as_string"],
            "attempts": attempts,
            "rate_per_minute": round(rate_per_min, 1)
        })
    
    total_attempts = int(result.get("aggregations", {}).get("overall", {}).get("value", 0) or 0)
    
    return {
        "time_range": time_range,
        "velocity": velocity_data,
        "total_attempts": total_attempts
    }
