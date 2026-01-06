"""Cowrie honeypot API routes."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
import statistics

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
    CowrieSession,
    CowrieCredential,
    CowrieCommand,
    CowrieHassh,
    CowrieVariantStats,
)

router = APIRouter()
INDEX = ".ds-cowrie-*"


async def get_duration_stats(es, time_range: str, variant_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Calculate duration statistics by fetching raw duration values from session.closed events.
    Supports both old (json.*) and new (cowrie.*) field structures.
    Duration can be in json.duration, cowrie.duration, or cowrie.duration_seconds.
    """
    must_clauses = [
        es._get_time_range_query(time_range),
        # Support both old (json.eventid) and new (cowrie.eventid) field structures
        {"bool": {"should": [
            {"term": {"json.eventid": "cowrie.session.closed"}},
            {"term": {"cowrie.eventid": "cowrie.session.closed"}}
        ], "minimum_should_match": 1}},
        # Duration can be in multiple fields
        {"bool": {"should": [
            {"exists": {"field": "json.duration"}},
            {"exists": {"field": "cowrie.duration"}},
            {"exists": {"field": "cowrie.duration_seconds"}}
        ], "minimum_should_match": 1}}
    ]
    
    if variant_filter:
        must_clauses.append({"term": {"cowrie_variant": variant_filter}})
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=10000,  # Get enough samples for accurate stats
        fields=["json.duration", "cowrie.duration", "cowrie.duration_seconds"]
    )
    
    durations = []
    for hit in result.get("hits", {}).get("hits", []):
        try:
            source = hit["_source"]
            # Try multiple field locations
            duration_val = (
                source.get("json", {}).get("duration") or
                source.get("cowrie", {}).get("duration") or
                source.get("cowrie", {}).get("duration_seconds")
            )
            if duration_val is not None:
                durations.append(float(duration_val))
        except (ValueError, TypeError):
            pass
    
    if not durations:
        return {
            "avg": 0,
            "max": 0,
            "min": 0,
            "p50": 0,
            "p90": 0,
            "p99": 0,
            "count": 0
        }
    
    durations_sorted = sorted(durations)
    
    def percentile(data: List[float], p: float) -> float:
        """Calculate percentile of sorted data."""
        if not data:
            return 0
        k = (len(data) - 1) * p / 100
        f = int(k)
        c = f + 1 if f + 1 < len(data) else f
        return data[f] + (k - f) * (data[c] - data[f]) if c != f else data[f]
    
    return {
        "avg": round(statistics.mean(durations), 2),
        "max": round(max(durations), 2),
        "min": round(min(durations), 2),
        "p50": round(percentile(durations_sorted, 50), 2),
        "p90": round(percentile(durations_sorted, 90), 2),
        "p99": round(percentile(durations_sorted, 99), 2),
        "count": len(durations)
    }


async def get_top_commands_by_variant(es, time_range: str, variant: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Get top commands for a specific variant. Supports both old and new field structures."""
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {
                        "bool": {
                            "should": [
                                {"term": {"json.eventid": "cowrie.command.input"}},
                                {"term": {"cowrie.eventid": "cowrie.command.input"}}
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    {"term": {"cowrie_variant": variant}}
                ]
            }
        },
        size=0,
        aggs={
            "top_commands": {
                "terms": {"field": "json.input", "size": limit}
            }
        }
    )
    
    return [
        {"command": b["key"], "count": b["doc_count"]}
        for b in result.get("aggregations", {}).get("top_commands", {}).get("buckets", [])
    ]


async def get_duration_distribution(es, time_range: str, variant_filter: Optional[str] = None, interval: int = 10) -> List[Dict[str, Any]]:
    """
    Calculate duration distribution histogram by fetching raw values.
    Returns buckets of durations grouped by interval (default 10 seconds).
    Supports both old (json.*) and new (cowrie.*) field structures.
    """
    must_clauses = [
        es._get_time_range_query(time_range),
        # Support both old (json.eventid) and new (cowrie.eventid) field structures
        {"bool": {"should": [
            {"term": {"json.eventid": "cowrie.session.closed"}},
            {"term": {"cowrie.eventid": "cowrie.session.closed"}}
        ], "minimum_should_match": 1}},
        # Duration can be in multiple fields
        {"bool": {"should": [
            {"exists": {"field": "json.duration"}},
            {"exists": {"field": "cowrie.duration"}},
            {"exists": {"field": "cowrie.duration_seconds"}}
        ], "minimum_should_match": 1}}
    ]
    
    if variant_filter:
        must_clauses.append({"term": {"cowrie_variant": variant_filter}})
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=10000,
        fields=["json.duration", "cowrie.duration", "cowrie.duration_seconds"]
    )
    
    # Collect durations
    durations = []
    for hit in result.get("hits", {}).get("hits", []):
        try:
            source = hit["_source"]
            # Try multiple field locations
            duration_val = (
                source.get("json", {}).get("duration") or
                source.get("cowrie", {}).get("duration") or
                source.get("cowrie", {}).get("duration_seconds")
            )
            if duration_val is not None:
                durations.append(float(duration_val))
        except (ValueError, TypeError):
            pass
    
    if not durations:
        return []
    
    # Build histogram buckets
    from collections import Counter
    buckets = Counter()
    for d in durations:
        bucket_key = int(d // interval) * interval
        buckets[bucket_key] += 1
    
    # Convert to sorted list of dicts
    return [
        {"duration_range": f"{key}-{key + interval}s", "count": count}
        for key, count in sorted(buckets.items())
    ]


@router.get("/stats", response_model=StatsResponse)
async def get_cowrie_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Cowrie honeypot statistics."""
    es = get_es_service()
    
    total_events = await es.get_total_events(INDEX, time_range)
    unique_ips = await es.get_unique_ips(INDEX, time_range)
    
    return StatsResponse(
        total_events=total_events,
        unique_ips=unique_ips,
        time_range=time_range
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_cowrie_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Cowrie event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    timeline = await es.get_timeline(INDEX, time_range, interval)
    
    return TimelineResponse(
        data=[TimelinePoint(**point) for point in timeline],
        time_range=time_range
    )


@router.get("/geo", response_model=GeoDistributionResponse)
async def get_cowrie_geo(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Cowrie geographic distribution."""
    es = get_es_service()
    
    geo_data = await es.get_geo_distribution(INDEX, time_range)
    
    return GeoDistributionResponse(
        data=[GeoPoint(**point) for point in geo_data],
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_cowrie_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top Cowrie attackers."""
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


@router.get("/sessions", response_model=List[CowrieSession])
async def get_cowrie_sessions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    min_duration: Optional[float] = Query(default=None, ge=0, description="Minimum session duration in seconds"),
    variant: Optional[str] = Query(default=None, description="Filter by cowrie variant"),
    has_commands: Optional[bool] = Query(default=None, description="Filter sessions with/without commands"),
    _: str = Depends(get_current_user)
):
    """Get Cowrie sessions with duration and command count. Supports filtering by duration, variant, and command presence."""
    es = get_es_service()
    
    # Build base query with optional filters
    must_clauses = [es._get_time_range_query(time_range)]
    if variant:
        must_clauses.append({"term": {"cowrie_variant": variant}})
    
    # If filtering for sessions WITH commands, first find those session IDs
    target_session_ids = None
    if has_commands is True:
        # Find sessions that have command events
        cmd_query = {"bool": {"must": must_clauses + [
            {"bool": {"should": [
                {"term": {"cowrie.eventid": "cowrie.command.input"}},
                {"term": {"json.eventid": "cowrie.command.input"}}
            ]}}
        ]}}
        
        cmd_result = await es.search(
            index=INDEX,
            query=cmd_query,
            size=0,
            aggs={
                "sessions_new": {"terms": {"field": "cowrie.session", "size": 1000}},
                "sessions_old": {"terms": {"field": "json.session", "size": 1000}}
            }
        )
        
        target_session_ids = set()
        for bucket in cmd_result.get("aggregations", {}).get("sessions_new", {}).get("buckets", []):
            target_session_ids.add(bucket["key"])
        for bucket in cmd_result.get("aggregations", {}).get("sessions_old", {}).get("buckets", []):
            target_session_ids.add(bucket["key"])
        
        if not target_session_ids:
            return []  # No sessions with commands found
    
    # Determine fetch size - need more if filtering
    fetch_size = limit * 10 if min_duration is not None or has_commands is False else limit
    
    query = {"bool": {"must": must_clauses}} if len(must_clauses) > 1 else es._get_time_range_query(time_range)
    
    # If we have specific target sessions, query them directly
    if target_session_ids:
        # Query sessions directly by their IDs
        sessions = []
        
        for session_id in list(target_session_ids)[:limit]:
            session_query = {"bool": {"must": [
                es._get_time_range_query(time_range),
                {"bool": {"should": [
                    {"term": {"cowrie.session": session_id}},
                    {"term": {"json.session": session_id}}
                ]}}
            ]}}
            
            if variant:
                session_query["bool"]["must"].append({"term": {"cowrie_variant": variant}})
            
            result = await es.search(
                index=INDEX,
                query=session_query,
                size=0,
                aggs={
                    "src_ip": {"top_hits": {"size": 1, "_source": ["cowrie.src_ip", "cowrie.geo.country_name", "json.src_ip", "source.geo.country_name", "cowrie_variant"]}},
                    "start_time": {"min": {"field": "@timestamp"}},
                    "end_time": {"max": {"field": "@timestamp"}},
                    "commands": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.command.input"}},
                        {"term": {"json.eventid": "cowrie.command.input"}}
                    ]}}},
                    "login_success": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.login.success"}},
                        {"term": {"json.eventid": "cowrie.login.success"}}
                    ]}}}
                }
            )
            
            if result.get("hits", {}).get("total", {}).get("value", 0) == 0:
                continue
            
            aggs = result.get("aggregations", {})
            hit_source = aggs.get("src_ip", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
            cowrie_data = hit_source.get("cowrie", {})
            json_data = hit_source.get("json", {})
            
            src_ip = cowrie_data.get("src_ip") or json_data.get("src_ip") or "unknown"
            country = cowrie_data.get("geo", {}).get("country_name") or hit_source.get("source", {}).get("geo", {}).get("country_name")
            
            start = aggs.get("start_time", {}).get("value_as_string")
            end = aggs.get("end_time", {}).get("value_as_string")
            
            duration = None
            if start and end:
                try:
                    from datetime import datetime
                    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    duration = (end_dt - start_dt).total_seconds()
                except:
                    pass
            
            if min_duration is not None and (duration is None or duration < min_duration):
                continue
            
            sessions.append(CowrieSession(
                session_id=session_id,
                src_ip=src_ip,
                start_time=start or "",
                end_time=end,
                duration=duration,
                commands_count=aggs.get("commands", {}).get("doc_count", 0),
                country=country,
                sensor=hit_source.get("cowrie_variant")
            ))
        
        sessions.sort(key=lambda x: -(x.duration or 0))
        return sessions
    
    # Standard aggregation query for non-targeted sessions
    result = await es.search(
        index=INDEX,
        query=query,
        size=0,
        aggs={
            "sessions_old": {
                "terms": {"field": "json.session", "size": fetch_size},
                "aggs": {
                    "src_ip": {"top_hits": {"size": 1, "_source": ["json.src_ip", "source.geo.country_name", "cowrie_variant"]}},
                    "start_time": {"min": {"field": "@timestamp"}},
                    "end_time": {"max": {"field": "@timestamp"}},
                    "commands": {"filter": {"term": {"json.eventid": "cowrie.command.input"}}},
                    "login_success": {"filter": {"term": {"json.eventid": "cowrie.login.success"}}}
                }
            },
            "sessions_new": {
                "terms": {"field": "cowrie.session", "size": fetch_size},
                "aggs": {
                    "src_ip": {"top_hits": {"size": 1, "_source": ["cowrie.src_ip", "cowrie.geo.country_name", "cowrie_variant"]}},
                    "start_time": {"min": {"field": "@timestamp"}},
                    "end_time": {"max": {"field": "@timestamp"}},
                    "commands": {"filter": {"term": {"cowrie.eventid": "cowrie.command.input"}}},
                    "login_success": {"filter": {"term": {"cowrie.eventid": "cowrie.login.success"}}}
                }
            }
        }
    )
    
    sessions = []
    seen_session_ids = set()
    
    # Process old format sessions
    for bucket in result.get("aggregations", {}).get("sessions_old", {}).get("buckets", []):
        session_id = bucket["key"]
        
        # Skip if we're filtering for specific sessions and this isn't one
        if target_session_ids is not None and session_id not in target_session_ids:
            continue
        if session_id in seen_session_ids:
            continue
        seen_session_ids.add(session_id)
        
        hit = bucket["src_ip"]["hits"]["hits"][0]["_source"] if bucket["src_ip"]["hits"]["hits"] else {}
        json_data = hit.get("json", {})
        geo_data = hit.get("source", {}).get("geo", {})
        src_ip = json_data.get("src_ip", "unknown")
        country = geo_data.get("country_name")
        
        start = bucket["start_time"]["value_as_string"] if bucket["start_time"].get("value_as_string") else None
        end = bucket["end_time"]["value_as_string"] if bucket["end_time"].get("value_as_string") else None
        
        duration = None
        if start and end:
            try:
                from datetime import datetime
                start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                duration = (end_dt - start_dt).total_seconds()
            except:
                pass
        
        session = CowrieSession(
            session_id=session_id,
            src_ip=src_ip,
            start_time=start or "",
            end_time=end,
            duration=duration,
            commands_count=bucket["commands"]["doc_count"],
            country=country,
            sensor=hit.get("cowrie_variant") or hit.get("observer", {}).get("name")
        )
        
        if min_duration is not None and (session.duration is None or session.duration < min_duration):
            continue
        # Skip has_commands filter here if we already filtered by target_session_ids
        if has_commands is not None and target_session_ids is None:
            if has_commands and session.commands_count == 0:
                continue
            if not has_commands and session.commands_count > 0:
                continue
        sessions.append(session)
    
    # Process new format sessions
    for bucket in result.get("aggregations", {}).get("sessions_new", {}).get("buckets", []):
        session_id = bucket["key"]
        
        # Skip if we're filtering for specific sessions and this isn't one
        if target_session_ids is not None and session_id not in target_session_ids:
            continue
        if session_id in seen_session_ids:
            continue
        seen_session_ids.add(session_id)
        
        hit = bucket["src_ip"]["hits"]["hits"][0]["_source"] if bucket["src_ip"]["hits"]["hits"] else {}
        cowrie_data = hit.get("cowrie", {})
        src_ip = cowrie_data.get("src_ip", "unknown")
        country = cowrie_data.get("geo", {}).get("country_name")
        
        start = bucket["start_time"]["value_as_string"] if bucket["start_time"].get("value_as_string") else None
        end = bucket["end_time"]["value_as_string"] if bucket["end_time"].get("value_as_string") else None
        
        duration = None
        if start and end:
            try:
                from datetime import datetime
                start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                duration = (end_dt - start_dt).total_seconds()
            except:
                pass
        
        session = CowrieSession(
            session_id=session_id,
            src_ip=src_ip,
            start_time=start or "",
            end_time=end,
            duration=duration,
            commands_count=bucket["commands"]["doc_count"],
            country=country,
            sensor=hit.get("cowrie_variant") or hit.get("observer", {}).get("name")
        )
        
        # Apply filters
        if min_duration is not None:
            if session.duration is None or session.duration < min_duration:
                continue
        
        # Skip has_commands filter if we already filtered by target_session_ids
        if has_commands is not None and target_session_ids is None:
            if has_commands and session.commands_count == 0:
                continue
            if not has_commands and session.commands_count > 0:
                continue
        
        sessions.append(session)
        
        # Stop once we have enough sessions after filtering
        if len(sessions) >= limit:
            break
    
    return sessions


@router.get("/sessions/interesting")
async def get_interesting_sessions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    min_duration: float = Query(default=5.0, ge=0, description="Minimum duration to be considered interesting"),
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(get_current_user)
):
    """
    Get 'interesting' sessions - those with duration > min_duration seconds.
    These are likely human attackers rather than automated scripts.
    Supports both old (json.*) and new (cowrie.*) field structures.
    """
    es = get_es_service()
    
    # Query for session.closed events with duration field - support both field structures
    # We need to fetch more and filter in Python because duration fields vary
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    # Support both old (json.eventid) and new (cowrie.eventid)
                    {"bool": {"should": [
                        {"term": {"json.eventid": "cowrie.session.closed"}},
                        {"term": {"cowrie.eventid": "cowrie.session.closed"}}
                    ], "minimum_should_match": 1}},
                    # Duration can be in multiple fields
                    {"bool": {"should": [
                        {"exists": {"field": "json.duration"}},
                        {"exists": {"field": "cowrie.duration"}},
                        {"exists": {"field": "cowrie.duration_seconds"}}
                    ], "minimum_should_match": 1}}
                ]
            }
        },
        size=limit * 5,  # Fetch more to filter by duration
        sort=[{"@timestamp": "desc"}]
    )
    
    sessions = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        cowrie_data = source.get("cowrie", {})
        geo_data = cowrie_data.get("geo", {}) or source.get("source", {}).get("geo", {})
        
        # Parse duration - try multiple field locations
        raw_duration = (
            json_data.get("duration") or
            cowrie_data.get("duration") or
            cowrie_data.get("duration_seconds")
        )
        try:
            duration = float(raw_duration) if raw_duration is not None else 0
        except (ValueError, TypeError):
            duration = 0
        
        # Filter by minimum duration
        if duration < min_duration:
            continue
        
        # Classify behavior based on duration
        if duration >= 60:
            behavior = "Human"
        elif duration >= 5:
            behavior = "Bot"
        else:
            behavior = "Script"
        
        # Get session ID and IP from either field structure
        session_id = json_data.get("session") or cowrie_data.get("session")
        src_ip = json_data.get("src_ip") or cowrie_data.get("src_ip") or "unknown"
        
        sessions.append({
            "session_id": session_id,
            "src_ip": src_ip,
            "duration": duration,
            "timestamp": source.get("@timestamp"),
            "country": geo_data.get("country_name"),
            "variant": source.get("cowrie_variant"),
            "behavior": behavior
        })
        
        if len(sessions) >= limit:
            break
    
    # Sort by duration descending
    sessions.sort(key=lambda x: -x["duration"])
    
    # Calculate stats
    durations = [s["duration"] for s in sessions if s["duration"] is not None]
    
    return {
        "sessions": sessions,
        "stats": {
            "total_interesting": len(sessions),
            "avg_duration": round(sum(durations) / len(durations), 2) if durations else 0,
            "max_duration": max(durations) if durations else 0,
            "min_duration_filter": min_duration,
            "human_count": len([s for s in sessions if s["behavior"] == "Human"]),
            "bot_count": len([s for s in sessions if s["behavior"] == "Bot"]),
        },
        "time_range": time_range
    }


@router.get("/credentials", response_model=List[CowrieCredential])
async def get_cowrie_credentials(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    variant: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get most common credential attempts."""
    es = get_es_service()
    
    # Build query for login events - support both old and new field structures
    must_clauses = [
        es._get_time_range_query(time_range),
        {
            "bool": {
                "should": [
                    {"term": {"json.eventid": "cowrie.login.success"}},
                    {"term": {"json.eventid": "cowrie.login.failed"}},
                    {"term": {"cowrie.eventid": "cowrie.login.success"}},
                    {"term": {"cowrie.eventid": "cowrie.login.failed"}}
                ],
                "minimum_should_match": 1
            }
        }
    ]
    
    # Filter by variant if specified
    if variant:
        must_clauses.append({"term": {"cowrie_variant": variant}})
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=limit * 2,  # Fetch more to account for aggregation
        sort=[{"@timestamp": "desc"}]
    )
    
    # Aggregate credentials manually - support both old (json.*) and new (cowrie.*) field structures
    cred_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        cowrie_data = source.get("cowrie", {})
        
        # Username/password in json.* (both old and new formats use json for the actual data)
        username = json_data.get("username", "")
        password = json_data.get("password", "")
        
        # Check eventid in both old and new locations
        eventid = json_data.get("eventid") or cowrie_data.get("eventid", "")
        success = eventid == "cowrie.login.success"
        
        if username:
            key = (username, password, success)
            cred_counts[key] = cred_counts.get(key, 0) + 1
    
    credentials = [
        CowrieCredential(
            username=key[0],
            password=key[1],
            count=count,
            success=key[2]
        )
        for key, count in sorted(cred_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return credentials


@router.get("/commands", response_model=List[CowrieCommand])
async def get_cowrie_commands(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    variant: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get most common commands executed."""
    es = get_es_service()
    
    # Support both old and new field structures
    must_clauses = [
        es._get_time_range_query(time_range),
        {
            "bool": {
                "should": [
                    {"term": {"json.eventid": "cowrie.command.input"}},
                    {"term": {"cowrie.eventid": "cowrie.command.input"}}
                ],
                "minimum_should_match": 1
            }
        }
    ]
    
    if variant:
        must_clauses.append({"term": {"cowrie_variant": variant}})
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=500,  # Fetch more to aggregate
        sort=[{"@timestamp": "desc"}]
    )
    
    # Aggregate commands - commands are in json.input field
    cmd_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        # Command is in json.input, not cowrie.input
        json_data = source.get("json", {})
        command = json_data.get("input", "")
        if command:
            # Truncate very long commands for display
            display_cmd = command[:200] + "..." if len(command) > 200 else command
            cmd_counts[display_cmd] = cmd_counts.get(display_cmd, 0) + 1
    
    commands = [
        CowrieCommand(
            command=cmd,
            count=count
        )
        for cmd, count in sorted(cmd_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return commands


@router.get("/session/{session_id}/commands")
async def get_session_commands(
    session_id: str,
    _: str = Depends(get_current_user)
):
    """Get all commands executed in a specific session."""
    es = get_es_service()
    
    # Support both old (json.*) and new (cowrie.*) field structures
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    {"bool": {
                        "should": [
                            {"term": {"json.session": session_id}},
                            {"term": {"cowrie.session": session_id}}
                        ],
                        "minimum_should_match": 1
                    }},
                    {"bool": {
                        "should": [
                            {"term": {"json.eventid": "cowrie.command.input"}},
                            {"term": {"cowrie.eventid": "cowrie.command.input"}}
                        ],
                        "minimum_should_match": 1
                    }}
                ]
            }
        },
        size=500,  # Increased to capture all commands
        sort=[{"@timestamp": "asc"}]
    )
    
    commands = []
    seen = set()
    last_command = None
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        cowrie_data = source.get("cowrie", {})
        # Command input can be in json.input or cowrie.input
        command = json_data.get("input", "") or cowrie_data.get("input", "")
        timestamp = source.get("@timestamp", "")
        
        if command:
            # Skip consecutive duplicate commands
            if command == last_command:
                continue
            
            # Normalize timestamp to second precision
            ts = timestamp
            if "." in ts:
                ts = ts.split(".")[0] + "Z"
            
            # Deduplicate by (timestamp, command)
            key = (ts, command)
            if key not in seen:
                seen.add(key)
                commands.append({
                    "command": command,
                    "timestamp": timestamp
                })
                last_command = command
    
    return {"session_id": session_id, "commands": commands, "total": len(commands)}


@router.get("/session/{session_id}/details")
async def get_session_details(
    session_id: str,
    _: str = Depends(get_current_user)
):
    """Get full session details including all events."""
    es = get_es_service()
    
    # Support both old (json.*) and new (cowrie.*) field structures
    result = await es.search(
        index=INDEX,
        query={"bool": {
            "should": [
                {"term": {"json.session": session_id}},
                {"term": {"cowrie.session": session_id}}
            ],
            "minimum_should_match": 1
        }},
        size=1000,  # Increased to capture all events in long sessions
        sort=[{"@timestamp": "asc"}]
    )
    
    events = []
    session_info = {}
    commands = []
    credentials = []
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        cowrie_data = source.get("cowrie", {})
        geo_data = cowrie_data.get("geo", {}) or source.get("source", {}).get("geo", {})
        event_id = cowrie_data.get("eventid", "") or json_data.get("eventid", "")
        timestamp = source.get("@timestamp", "")
        
        event = {
            "type": event_id,
            "timestamp": timestamp,
            "details": {}
        }
        
        # Extract session info from first connect event
        if event_id == "cowrie.session.connect" and not session_info:
            session_info = {
                "src_ip": cowrie_data.get("src_ip") or json_data.get("src_ip"),
                "country": geo_data.get("country_name"),
                "city": geo_data.get("city_name"),
                "sensor": source.get("cowrie_variant") or cowrie_data.get("sensor") or source.get("observer", {}).get("name"),
                "protocol": json_data.get("protocol"),
                "start_time": timestamp
            }
        
        # Extract session duration from closed event
        if event_id == "cowrie.session.closed":
            session_info["end_time"] = timestamp
            duration = json_data.get("duration") or cowrie_data.get("duration")
            if duration:
                session_info["duration"] = duration
        
        # Extract commands (check both json.input and cowrie.input)
        if event_id == "cowrie.command.input":
            cmd = json_data.get("input", "") or cowrie_data.get("input", "")
            if cmd:
                commands.append({"command": cmd, "timestamp": timestamp})
                event["details"]["command"] = cmd
        
        # Extract login attempts (check both field structures)
        if event_id in ["cowrie.login.success", "cowrie.login.failed"]:
            username = json_data.get("username", "") or cowrie_data.get("username", "")
            password = json_data.get("password", "") or cowrie_data.get("password", "")
            credentials.append({
                "username": username,
                "password": password,
                "success": event_id == "cowrie.login.success",
                "timestamp": timestamp
            })
            event["details"]["username"] = username
            event["details"]["password"] = password
            event["details"]["success"] = event_id == "cowrie.login.success"
        
        # Extract file downloads
        if event_id == "cowrie.session.file_download":
            event["details"]["url"] = json_data.get("url", "") or cowrie_data.get("url", "")
            event["details"]["sha256"] = json_data.get("sha256", "") or cowrie_data.get("sha256", "")
        
        # Extract client info
        if event_id == "cowrie.client.version":
            version = json_data.get("version", "") or cowrie_data.get("version", "")
            event["details"]["version"] = version
            session_info["client_version"] = version
        
        events.append(event)
    
    # Deduplicate commands more aggressively:
    # 1. Normalize timestamps to the second (ignore milliseconds)
    # 2. Skip consecutive identical commands
    seen_commands = set()
    unique_commands = []
    last_command = None
    
    for cmd in commands:
        # Normalize timestamp to second precision for deduplication
        ts = cmd["timestamp"]
        if "." in ts:
            ts = ts.split(".")[0] + "Z"  # Remove milliseconds
        
        # Skip if this is the same command as the last one (consecutive duplicate)
        if cmd["command"] == last_command:
            continue
        
        key = (ts, cmd["command"])
        if key not in seen_commands:
            seen_commands.add(key)
            unique_commands.append(cmd)
            last_command = cmd["command"]
    
    return {
        "session_id": session_id,
        "info": session_info,
        "commands": unique_commands,
        "credentials": credentials,
        "events": events,
        "total_events": len(events)
    }


@router.get("/hassh", response_model=List[CowrieHassh])
async def get_cowrie_hassh(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get SSH fingerprints (HASSH)."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"json.eventid": "cowrie.client.kex"}}
                ]
            }
        },
        size=limit,
        sort=[{"@timestamp": "desc"}],
        fields=["cowrie.hassh", "cowrie.version", "cowrie.kexAlgs"]
    )
    
    # Aggregate HASSH
    hassh_counts = {}
    hassh_versions = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        hassh = json_data.get("hassh", "")
        version = json_data.get("version", "")
        
        if hassh:
            hassh_counts[hassh] = hassh_counts.get(hassh, 0) + 1
            if version:
                hassh_versions[hassh] = version
    
    hassh_list = [
        CowrieHassh(
            hassh=h,
            count=count,
            client_version=hassh_versions.get(h)
        )
        for h, count in sorted(hassh_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return hassh_list


@router.get("/variants")
async def get_cowrie_variants(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Compare Cowrie variants with comprehensive metrics.
    Uses cowrie_variant field which has values: plain, openai, ollama
    """
    es = get_es_service()
    
    # Aggregate by cowrie_variant field which identifies the sensor type
    # Support both old (json.*) and new (cowrie.*) field structures
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "variants": {
                "terms": {
                    "field": "cowrie_variant",  # plain, openai, ollama
                    "size": 10
                },
                "aggs": {
                    # Support both old and new field structures
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}},
                    "sessions_old": {"cardinality": {"field": "json.session"}},
                    "sessions_new": {"cardinality": {"field": "cowrie.session"}},
                    "commands_old": {
                        "filter": {"term": {"json.eventid": "cowrie.command.input"}}
                    },
                    "commands_new": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.command.input"}}
                    },
                    "login_success_old": {
                        "filter": {"term": {"json.eventid": "cowrie.login.success"}}
                    },
                    "login_success_new": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.login.success"}}
                    },
                    "login_failed_old": {
                        "filter": {"term": {"json.eventid": "cowrie.login.failed"}}
                    },
                    "login_failed_new": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.login.failed"}}
                    },
                    "file_downloads_old": {
                        "filter": {"term": {"json.eventid": "cowrie.session.file_download"}}
                    },
                    "file_downloads_new": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.session.file_download"}}
                    }
                }
            }
        }
    )
    
    variants = []
    for bucket in result.get("aggregations", {}).get("variants", {}).get("buckets", []):
        # Combine old and new field values (use max since they're the same data in different formats)
        unique_ips = max(
            bucket.get("unique_ips_old", {}).get("value", 0),
            bucket.get("unique_ips_new", {}).get("value", 0)
        )
        sessions = max(
            bucket.get("sessions_old", {}).get("value", 0),
            bucket.get("sessions_new", {}).get("value", 0)
        )
        commands = (
            bucket.get("commands_old", {}).get("doc_count", 0) +
            bucket.get("commands_new", {}).get("doc_count", 0)
        )
        login_success = (
            bucket.get("login_success_old", {}).get("doc_count", 0) +
            bucket.get("login_success_new", {}).get("doc_count", 0)
        )
        login_failed = (
            bucket.get("login_failed_old", {}).get("doc_count", 0) +
            bucket.get("login_failed_new", {}).get("doc_count", 0)
        )
        file_downloads = (
            bucket.get("file_downloads_old", {}).get("doc_count", 0) +
            bucket.get("file_downloads_new", {}).get("doc_count", 0)
        )
        
        # Calculate login success rate
        total_logins = login_success + login_failed
        success_rate = (login_success / total_logins * 100) if total_logins > 0 else 0
        
        # Determine variant display name (cowrie_variant values: plain, openai, ollama)
        variant_key = bucket["key"]
        variant_display_names = {
            "plain": "Plain (Standard)",
            "openai": "OpenAI (GPT)",
            "ollama": "Ollama (Local LLM)",
        }
        display_name = variant_display_names.get(variant_key, variant_key.title())
        
        # Get duration stats for this variant (calculated in Python since json.duration is a string field)
        duration_stats = await get_duration_stats(es, time_range, variant_key)
        
        variants.append({
            "variant": variant_key,
            "display_name": display_name,
            "total_events": bucket["doc_count"],
            "unique_ips": unique_ips,
            "sessions_count": sessions,
            "commands_count": commands,
            "login_success": login_success,
            "login_failed": login_failed,
            "success_rate": round(success_rate, 1),
            "file_downloads": file_downloads,
            "avg_session_duration": duration_stats["avg"],
        })
    
    return {"variants": variants, "time_range": time_range}


@router.get("/variant/{variant}/stats")
async def get_cowrie_variant_stats(
    variant: str,
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get detailed statistics for a specific Cowrie variant."""
    es = get_es_service()
    
    # Query for specific variant using cowrie_variant field
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"cowrie_variant": variant}}
                ]
            }
        },
        size=0,
        aggs={
            "event_types": {
                "terms": {"field": "json.eventid", "size": 20}
            },
            "top_commands": {
                "filter": {"term": {"json.eventid": "cowrie.command.input"}},
                "aggs": {
                    "commands": {
                        "terms": {"field": "json.input", "size": 10}
                    }
                }
            },
            "top_countries": {
                "terms": {"field": "source.geo.country_name", "size": 10}
            },
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h" if time_range == "24h" else "6h"
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    # Get duration distribution (calculated in Python since json.duration is a string field)
    duration_distribution = await get_duration_distribution(es, time_range, variant)
    
    return {
        "variant": variant,
        "time_range": time_range,
        "event_types": [
            {"event": b["key"], "count": b["doc_count"]}
            for b in aggs.get("event_types", {}).get("buckets", [])
        ],
        "top_commands": [
            {"command": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_commands", {}).get("commands", {}).get("buckets", [])
        ],
        "top_countries": [
            {"country": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_countries", {}).get("buckets", [])
        ],
        "duration_distribution": duration_distribution,
        "timeline": [
            {"timestamp": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs.get("timeline", {}).get("buckets", [])
        ]
    }


@router.get("/variant-comparison")
async def get_cowrie_variant_comparison(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get side-by-side comparison data for Cowrie variants.
    Includes metrics for comparing plain vs LLM effectiveness.
    """
    es = get_es_service()
    
    # Support both old (json.*) and new (cowrie.*) field structures
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_variant": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    # Session metrics - both old and new formats
                    "session_count_old": {"cardinality": {"field": "json.session"}},
                    "session_count_new": {"cardinality": {"field": "cowrie.session"}},
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}},
                    # Login metrics - both formats
                    "login_success_old": {"filter": {"term": {"json.eventid": "cowrie.login.success"}}},
                    "login_success_new": {"filter": {"term": {"cowrie.eventid": "cowrie.login.success"}}},
                    "login_failed_old": {"filter": {"term": {"json.eventid": "cowrie.login.failed"}}},
                    "login_failed_new": {"filter": {"term": {"cowrie.eventid": "cowrie.login.failed"}}},
                    # Command metrics - both formats
                    "commands_old": {
                        "filter": {"term": {"json.eventid": "cowrie.command.input"}},
                        "aggs": {"unique_commands": {"cardinality": {"field": "json.input"}}}
                    },
                    "commands_new": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.command.input"}},
                        "aggs": {"unique_commands": {"cardinality": {"field": "json.input"}}}
                    },
                    # Downloads - both formats
                    "downloads_old": {"filter": {"term": {"json.eventid": "cowrie.session.file_download"}}},
                    "downloads_new": {"filter": {"term": {"cowrie.eventid": "cowrie.session.file_download"}}},
                    # Timeline for comparison
                    "hourly": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1h"
                        }
                    }
                }
            }
        }
    )
    
    comparison = []
    for bucket in result.get("aggregations", {}).get("by_variant", {}).get("buckets", []):
        # Combine old and new format values
        login_success = (
            bucket.get("login_success_old", {}).get("doc_count", 0) +
            bucket.get("login_success_new", {}).get("doc_count", 0)
        )
        login_failed = (
            bucket.get("login_failed_old", {}).get("doc_count", 0) +
            bucket.get("login_failed_new", {}).get("doc_count", 0)
        )
        total_logins = login_success + login_failed
        
        commands_count = (
            bucket.get("commands_old", {}).get("doc_count", 0) +
            bucket.get("commands_new", {}).get("doc_count", 0)
        )
        unique_commands = (
            bucket.get("commands_old", {}).get("unique_commands", {}).get("value", 0) +
            bucket.get("commands_new", {}).get("unique_commands", {}).get("value", 0)
        )
        unique_ips = max(
            bucket.get("unique_ips_old", {}).get("value", 0),
            bucket.get("unique_ips_new", {}).get("value", 0)
        )
        sessions = max(
            bucket.get("session_count_old", {}).get("value", 0),
            bucket.get("session_count_new", {}).get("value", 0)
        )
        downloads = (
            bucket.get("downloads_old", {}).get("doc_count", 0) +
            bucket.get("downloads_new", {}).get("doc_count", 0)
        )
        
        variant_key = bucket["key"]
        variant_display_names = {
            "plain": "Plain (Standard)",
            "openai": "OpenAI (GPT)",
            "ollama": "Ollama (Local LLM)",
        }
        
        # Get duration stats for this variant (calculated in Python since json.duration is a string field)
        duration_stats = await get_duration_stats(es, time_range, variant_key)
        
        # Get top commands for this variant
        top_commands = await get_top_commands_by_variant(es, time_range, variant_key, limit=10)
        
        comparison.append({
            "variant": variant_key,
            "display_name": variant_display_names.get(variant_key, variant_key.title()),
            "metrics": {
                "total_events": bucket["doc_count"],
                "unique_ips": unique_ips,
                "sessions": sessions,
                "login_success": login_success,
                "login_failed": login_failed,
                "login_success_rate": round(login_success / total_logins * 100, 1) if total_logins > 0 else 0,
                "commands_executed": commands_count,
                "unique_commands": unique_commands,
                "file_downloads": downloads,
            },
            "duration": duration_stats,
            "top_commands": top_commands,
            "timeline": [
                {"timestamp": b["key_as_string"], "count": b["doc_count"]}
                for b in bucket.get("hourly", {}).get("buckets", [])
            ]
        })
    
    return {"comparison": comparison, "time_range": time_range}


@router.get("/logs")
async def get_cowrie_logs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    event_type: Optional[str] = Query(default=None),
    session_id: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get Cowrie logs with filtering options."""
    es = get_es_service()
    
    filters = {}
    if event_type:
        filters["json.eventid"] = event_type
    if session_id:
        filters["json.session"] = session_id
    if src_ip:
        filters["json.src_ip"] = src_ip
    
    return await es.get_logs(INDEX, time_range, limit, search, filters)


@router.get("/heatmap")
async def get_cowrie_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly heatmap data for Cowrie."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    return {"data": heatmap_data, "time_range": time_range}


@router.get("/login-analysis")
async def get_cowrie_login_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get login success/failure analysis by sensor variant."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"terms": {"json.eventid": ["cowrie.login.failed", "cowrie.login.success"]}}
        ]}},
        size=0,
        aggs={
            "by_sensor": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    "by_result": {
                        "terms": {"field": "json.eventid", "size": 10}
                    }
                }
            }
        }
    )
    
    # Process results
    sensor_data = []
    for sensor_bucket in result.get("aggregations", {}).get("by_sensor", {}).get("buckets", []):
        sensor_name = sensor_bucket["key"]
        success = 0
        failed = 0
        for result_bucket in sensor_bucket.get("by_result", {}).get("buckets", []):
            event = result_bucket["key"]
            count = result_bucket["doc_count"]
            if "success" in event:
                success = count
            elif "failed" in event:
                failed = count
        sensor_data.append({
            "sensor": sensor_name,
            "success": success,
            "failed": failed,
            "total": success + failed,
            "success_rate": round(success / (success + failed) * 100, 1) if (success + failed) > 0 else 0
        })
    
    return {"time_range": time_range, "sensors": sensor_data}


@router.get("/session-durations")
async def get_cowrie_session_durations(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get session duration distribution. Supports both old and new field structures."""
    es = get_es_service()
    
    # First, fetch raw duration data since field names vary
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            # Support multiple duration field locations
            {"bool": {"should": [
                {"exists": {"field": "json.duration"}},
                {"exists": {"field": "cowrie.duration"}},
                {"exists": {"field": "cowrie.duration_seconds"}}
            ], "minimum_should_match": 1}}
        ]}},
        size=10000,
        fields=["json.duration", "cowrie.duration", "cowrie.duration_seconds"]
    )
    
    # Collect durations manually
    durations = []
    for hit in result.get("hits", {}).get("hits", []):
        try:
            source = hit["_source"]
            duration_val = (
                source.get("json", {}).get("duration") or
                source.get("cowrie", {}).get("duration") or
                source.get("cowrie", {}).get("duration_seconds")
            )
            if duration_val is not None:
                durations.append(float(duration_val))
        except (ValueError, TypeError):
            pass
    
    # Build ranges manually
    range_buckets = {
        "0-10s": 0,
        "10-30s": 0,
        "30s-1m": 0,
        "1-5m": 0,
        "5-15m": 0,
        "15m+": 0
    }
    
    for d in durations:
        if d < 10:
            range_buckets["0-10s"] += 1
        elif d < 30:
            range_buckets["10-30s"] += 1
        elif d < 60:
            range_buckets["30s-1m"] += 1
        elif d < 300:
            range_buckets["1-5m"] += 1
        elif d < 900:
            range_buckets["5-15m"] += 1
        else:
            range_buckets["15m+"] += 1
    
    ranges = [{"range": k, "count": v} for k, v in range_buckets.items()]
    
    # Calculate stats
    if durations:
        durations_sorted = sorted(durations)
        
        def percentile(data: List[float], p: float) -> float:
            if not data:
                return 0
            k = (len(data) - 1) * p / 100
            f = int(k)
            c = f + 1 if f + 1 < len(data) else f
            return data[f] + (k - f) * (data[c] - data[f]) if c != f else data[f]
        
        stats = {
            "avg_duration": round(sum(durations) / len(durations), 1),
            "max_duration": round(max(durations), 1),
            "percentiles": {
                "50.0": round(percentile(durations_sorted, 50), 1),
                "75.0": round(percentile(durations_sorted, 75), 1),
                "90.0": round(percentile(durations_sorted, 90), 1),
                "95.0": round(percentile(durations_sorted, 95), 1)
            }
        }
    else:
        stats = {
            "avg_duration": 0,
            "max_duration": 0,
            "percentiles": {"50.0": None, "75.0": None, "90.0": None, "95.0": None}
        }
    
    return {"time_range": time_range, "ranges": ranges, "stats": stats}


@router.get("/attack-funnel")
async def get_cowrie_attack_funnel(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get attack progression funnel: connect -> login attempt -> success -> commands."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_event": {
                "terms": {"field": "json.eventid", "size": 50}
            },
            "unique_sessions": {
                "cardinality": {"field": "json.session"}
            }
        }
    )
    
    event_counts = {}
    for bucket in result.get("aggregations", {}).get("by_event", {}).get("buckets", []):
        event_counts[bucket["key"]] = bucket["doc_count"]
    
    # Calculate funnel stages
    connects = event_counts.get("cowrie.session.connect", 0)
    login_attempts = event_counts.get("cowrie.login.failed", 0) + event_counts.get("cowrie.login.success", 0)
    login_success = event_counts.get("cowrie.login.success", 0)
    commands = event_counts.get("cowrie.command.input", 0) + event_counts.get("cowrie.command.failed", 0)
    
    funnel = [
        {"stage": "Connections", "count": connects, "percentage": 100},
        {"stage": "Login Attempts", "count": login_attempts, "percentage": round(login_attempts / connects * 100, 1) if connects > 0 else 0},
        {"stage": "Login Success", "count": login_success, "percentage": round(login_success / connects * 100, 1) if connects > 0 else 0},
        {"stage": "Commands Executed", "count": commands, "percentage": round(commands / connects * 100, 1) if connects > 0 else 0},
    ]
    
    return {
        "time_range": time_range,
        "funnel": funnel,
        "total_sessions": result.get("aggregations", {}).get("unique_sessions", {}).get("value", 0)
    }


@router.get("/credential-reuse")
async def get_cowrie_credential_reuse(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get credential reuse analysis - which passwords are tried multiple times."""
    es = get_es_service()
    
    # Check both cowrie.* and json.* field locations
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"bool": {"should": [
                {"exists": {"field": "cowrie.password"}},
                {"exists": {"field": "json.password"}}
            ]}}
        ]}},
        size=0,
        aggs={
            "top_passwords": {
                "terms": {"field": "cowrie.password", "size": 15, "min_doc_count": 2}
            },
            "json_passwords": {
                "terms": {"field": "json.password", "size": 15, "min_doc_count": 2}
            },
            "top_usernames": {
                "terms": {"field": "cowrie.username", "size": 15, "min_doc_count": 2}
            },
            "json_usernames": {
                "terms": {"field": "json.username", "size": 15, "min_doc_count": 2}
            },
            "unique_ips_with_creds": {
                "cardinality": {"field": "json.src_ip"}
            }
        }
    )
    
    # Combine password data from both locations
    password_counts = {}
    for bucket in result.get("aggregations", {}).get("top_passwords", {}).get("buckets", []):
        password_counts[bucket["key"]] = password_counts.get(bucket["key"], 0) + bucket["doc_count"]
    for bucket in result.get("aggregations", {}).get("json_passwords", {}).get("buckets", []):
        password_counts[bucket["key"]] = password_counts.get(bucket["key"], 0) + bucket["doc_count"]
    
    # Combine username data
    username_counts = {}
    for bucket in result.get("aggregations", {}).get("top_usernames", {}).get("buckets", []):
        username_counts[bucket["key"]] = username_counts.get(bucket["key"], 0) + bucket["doc_count"]
    for bucket in result.get("aggregations", {}).get("json_usernames", {}).get("buckets", []):
        username_counts[bucket["key"]] = username_counts.get(bucket["key"], 0) + bucket["doc_count"]
    
    # Sort and convert
    top_passwords = [{"password": k, "count": v} for k, v in sorted(password_counts.items(), key=lambda x: -x[1])[:15]]
    top_usernames = [{"username": k, "count": v} for k, v in sorted(username_counts.items(), key=lambda x: -x[1])[:15]]
    
    return {
        "time_range": time_range,
        "top_passwords": top_passwords,
        "top_usernames": top_usernames,
        "unique_sources": result.get("aggregations", {}).get("unique_ips_with_creds", {}).get("value", 0)
    }


@router.get("/client-fingerprints")
async def get_cowrie_client_fingerprints(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get SSH client fingerprinting analysis based on version strings and HASSH."""
    es = get_es_service()
    
    # Get SSH version string distribution
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"json.eventid": "cowrie.client.version"}}
        ]}},
        size=0,
        aggs={
            "ssh_versions": {
                "terms": {"field": "json.version", "size": 50}
            },
            "hassh_fingerprints": {
                "terms": {"field": "json.hassh", "size": 30}
            },
            "unique_clients": {
                "cardinality": {"field": "json.hassh"}
            }
        }
    )
    
    # Categorize SSH versions to known tools
    tool_categories = {
        "Go": "Go SSH (Automated Scanner)",
        "Paramiko": "Paramiko (Python Tool)",
        "libssh": "libssh (C Library)",
        "OpenSSH": "OpenSSH (Standard Client)",
        "PuTTY": "PuTTY (Windows Client)",
        "Dropbear": "Dropbear (Embedded)",
        "AsyncSSH": "AsyncSSH (Python)",
        "JSCH": "JSCH (Java)",
        "WinSCP": "WinSCP (Windows)",
        "Tera": "Tera Term",
        "Bitvise": "Bitvise SSH",
        "SSH2": "SSH2 Library",
        "ROSSSH": "ROS SSH",
    }
    
    version_buckets = result.get("aggregations", {}).get("ssh_versions", {}).get("buckets", [])
    tool_counts = {}
    version_details = []
    
    for bucket in version_buckets:
        version = bucket["key"]
        count = bucket["doc_count"]
        
        # Try to identify the tool
        identified_tool = "Unknown"
        for pattern, tool_name in tool_categories.items():
            if pattern.lower() in version.lower():
                identified_tool = tool_name
                break
        
        tool_counts[identified_tool] = tool_counts.get(identified_tool, 0) + count
        version_details.append({
            "version": version,
            "count": count,
            "tool": identified_tool,
        })
    
    # Sort tool counts
    tools = [{"tool": k, "count": v} for k, v in sorted(tool_counts.items(), key=lambda x: -x[1])]
    
    # Get HASSH fingerprints
    hassh_buckets = result.get("aggregations", {}).get("hassh_fingerprints", {}).get("buckets", [])
    fingerprints = [{"hassh": b["key"], "count": b["doc_count"]} for b in hassh_buckets]
    
    return {
        "time_range": time_range,
        "tools": tools,
        "versions": sorted(version_details, key=lambda x: -x["count"])[:30],
        "fingerprints": fingerprints,
        "unique_fingerprints": result.get("aggregations", {}).get("unique_clients", {}).get("value", 0)
    }


@router.get("/weak-algorithms")
async def get_cowrie_weak_algorithms(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Detect usage of weak SSH algorithms."""
    es = get_es_service()
    
    # Weak algorithms to check for
    weak_algorithms = {
        "ciphers": ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "aes128-cbc", "blowfish-cbc", "cast128-cbc"],
        "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"],
        "mac": ["hmac-sha1-96", "hmac-md5", "hmac-md5-96"],
    }
    
    # Get KEX events with algorithm info
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"json.eventid": "cowrie.client.kex"}}
        ]}},
        size=1000,
        fields=["json.encCS", "json.kexAlgs", "json.macCS", "json.src_ip", "@timestamp"]
    )
    
    weak_usage = {
        "ciphers": {},
        "kex": {},
        "mac": {},
    }
    
    attackers_with_weak = set()
    total_sessions = len(result.get("hits", {}).get("hits", []))
    sessions_with_weak = 0
    
    for hit in result.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        json_data = src.get("json", {})
        has_weak = False
        
        # Check ciphers
        enc_cs = json_data.get("encCS", [])
        if isinstance(enc_cs, list):
            for cipher in enc_cs:
                if cipher.lower() in [w.lower() for w in weak_algorithms["ciphers"]]:
                    weak_usage["ciphers"][cipher] = weak_usage["ciphers"].get(cipher, 0) + 1
                    has_weak = True
        
        # Check key exchange
        kex_algs = json_data.get("kexAlgs", [])
        if isinstance(kex_algs, list):
            for kex in kex_algs:
                if kex.lower() in [w.lower() for w in weak_algorithms["kex"]]:
                    weak_usage["kex"][kex] = weak_usage["kex"].get(kex, 0) + 1
                    has_weak = True
        
        # Check MAC
        mac_cs = json_data.get("macCS", [])
        if isinstance(mac_cs, list):
            for mac in mac_cs:
                if mac.lower() in [w.lower() for w in weak_algorithms["mac"]]:
                    weak_usage["mac"][mac] = weak_usage["mac"].get(mac, 0) + 1
                    has_weak = True
        
        if has_weak:
            sessions_with_weak += 1
            src_ip = src.get("json", {}).get("src_ip")
            if src_ip:
                attackers_with_weak.add(src_ip)
    
    # Convert to lists
    weak_ciphers = [{"algorithm": k, "count": v, "type": "cipher"} for k, v in sorted(weak_usage["ciphers"].items(), key=lambda x: -x[1])]
    weak_kex = [{"algorithm": k, "count": v, "type": "kex"} for k, v in sorted(weak_usage["kex"].items(), key=lambda x: -x[1])]
    weak_mac = [{"algorithm": k, "count": v, "type": "mac"} for k, v in sorted(weak_usage["mac"].items(), key=lambda x: -x[1])]
    
    return {
        "time_range": time_range,
        "weak_ciphers": weak_ciphers,
        "weak_kex": weak_kex,
        "weak_mac": weak_mac,
        "summary": {
            "total_sessions": total_sessions,
            "sessions_with_weak": sessions_with_weak,
            "weak_percentage": round(sessions_with_weak / total_sessions * 100, 1) if total_sessions > 0 else 0,
            "unique_attackers_with_weak": len(attackers_with_weak)
        }
    }


@router.get("/command-categories")
async def get_cowrie_command_categories(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Categorize executed commands with MITRE ATT&CK mapping."""
    from app.services.mitre import categorize_command, MITRE_TECHNIQUES
    
    es = get_es_service()
    
    # Get commands - support both old (json.eventid) and new (cowrie.eventid) field structures
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"exists": {"field": "json.input"}},
            {
                "bool": {
                    "should": [
                        {"term": {"json.eventid": "cowrie.command.input"}},
                        {"term": {"cowrie.eventid": "cowrie.command.input"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        ]}},
        size=0,
        aggs={
            "commands": {
                "terms": {"field": "json.input", "size": 200}
            }
        }
    )
    
    categories = {
        "Reconnaissance": 0,
        "Discovery": 0,
        "Execution": 0,
        "Download/Exfiltration": 0,
        "Other": 0,
    }
    
    technique_counts = {}
    command_details = []
    
    for bucket in result.get("aggregations", {}).get("commands", {}).get("buckets", []):
        command = bucket["key"]
        count = bucket["doc_count"]
        
        analysis = categorize_command(command)
        
        for cat in analysis["categories"]:
            if cat in categories:
                categories[cat] += count
        
        for tech_id in analysis["techniques"]:
            technique_counts[tech_id] = technique_counts.get(tech_id, 0) + count
        
        command_details.append({
            "command": command[:100] + "..." if len(command) > 100 else command,
            "count": count,
            "categories": analysis["categories"],
            "techniques": analysis["techniques"],
        })
    
    # Get top techniques with details
    top_techniques = []
    for tech_id, count in sorted(technique_counts.items(), key=lambda x: -x[1])[:10]:
        tech_info = MITRE_TECHNIQUES.get(tech_id, {})
        top_techniques.append({
            "id": tech_id,
            "name": tech_info.get("name", "Unknown"),
            "tactic": tech_info.get("tactic", "Unknown"),
            "count": count,
        })
    
    return {
        "time_range": time_range,
        "categories": [{"category": k, "count": v} for k, v in sorted(categories.items(), key=lambda x: -x[1])],
        "techniques": top_techniques,
        "commands": sorted(command_details, key=lambda x: -x["count"])[:50],
        "total_commands": sum(categories.values())
    }


# Command intent explanations
COMMAND_INTENTS = {
    "reconnaissance": {
        "description": "System information gathering",
        "patterns": ["uname", "whoami", "id", "hostname", "cat /proc", "lscpu", "free", "df", "ps", "top", "w ", "who"],
        "mitre": "T1082 - System Information Discovery",
        "risk": "low"
    },
    "network_recon": {
        "description": "Network configuration discovery",
        "patterns": ["ifconfig", "ip addr", "netstat", "ss ", "route", "arp", "ping", "nslookup", "dig"],
        "mitre": "T1016 - System Network Configuration Discovery",
        "risk": "low"
    },
    "credential_access": {
        "description": "Credential theft or access",
        "patterns": ["/etc/passwd", "/etc/shadow", "cat /etc", "history", ".bash_history", ".ssh/", "id_rsa"],
        "mitre": "T1552 - Unsecured Credentials",
        "risk": "high"
    },
    "download_execute": {
        "description": "Malware download and execution",
        "patterns": ["wget", "curl", "tftp", "ftp", "scp", "nc ", "netcat"],
        "mitre": "T1105 - Ingress Tool Transfer",
        "risk": "critical"
    },
    "persistence": {
        "description": "Establishing persistent access",
        "patterns": ["crontab", "systemctl", "service", "chkconfig", "/etc/rc", "authorized_keys", ".bashrc"],
        "mitre": "T1053 - Scheduled Task/Job",
        "risk": "high"
    },
    "privilege_escalation": {
        "description": "Attempting to gain higher privileges",
        "patterns": ["sudo", "su ", "chmod +s", "setuid", "pkexec", "doas"],
        "mitre": "T1548 - Abuse Elevation Control Mechanism",
        "risk": "high"
    },
    "defense_evasion": {
        "description": "Hiding presence or clearing evidence",
        "patterns": ["rm ", "unset HISTFILE", "history -c", "shred", "chattr", "> /var/log"],
        "mitre": "T1070 - Indicator Removal",
        "risk": "medium"
    },
    "execution": {
        "description": "Running malicious scripts or binaries",
        "patterns": ["chmod +x", "bash ", "sh ", "python", "perl", "ruby", "./", "nohup"],
        "mitre": "T1059 - Command and Scripting Interpreter",
        "risk": "medium"
    },
    "cryptomining": {
        "description": "Cryptocurrency mining preparation",
        "patterns": ["xmrig", "minerd", "cpulimit", "nicehash", "stratum", "pool."],
        "mitre": "T1496 - Resource Hijacking",
        "risk": "high"
    },
    "lateral_movement": {
        "description": "Moving to other systems",
        "patterns": ["ssh ", "sshpass", "psexec", "rsh ", "rlogin"],
        "mitre": "T1021 - Remote Services",
        "risk": "high"
    },
    "navigation": {
        "description": "Filesystem navigation",
        "patterns": ["cd ", "ls", "pwd", "dir", "find", "locate"],
        "mitre": "T1083 - File and Directory Discovery",
        "risk": "low"
    },
    "environment": {
        "description": "Environment configuration",
        "patterns": ["export", "PATH=", "set ", "env", "printenv"],
        "mitre": "T1480 - Execution Guardrails",
        "risk": "low"
    }
}


def classify_command(command: str) -> dict:
    """Classify a command and return its intent information."""
    cmd_lower = command.lower()
    
    for intent_key, intent_info in COMMAND_INTENTS.items():
        for pattern in intent_info["patterns"]:
            if pattern.lower() in cmd_lower:
                return {
                    "intent": intent_key,
                    "description": intent_info["description"],
                    "mitre": intent_info["mitre"],
                    "risk": intent_info["risk"]
                }
    
    return {
        "intent": "unknown",
        "description": "Unknown command purpose",
        "mitre": None,
        "risk": "low"
    }


@router.get("/commands/explorer")
async def get_cowrie_command_explorer(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    category: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """
    Get detailed command exploration data with intent analysis.
    """
    es = get_es_service()
    
    # Get all commands with context - support both old and new field structures
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {
                "bool": {
                    "should": [
                        {"term": {"json.eventid": "cowrie.command.input"}},
                        {"term": {"cowrie.eventid": "cowrie.command.input"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        ]}},
        size=0,
        aggs={
            "commands": {
                "terms": {"field": "json.input", "size": 200},
                "aggs": {
                    "by_variant": {"terms": {"field": "cowrie_variant", "size": 10}},
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}},
                    "sessions_old": {"cardinality": {"field": "json.session"}},
                    "sessions_new": {"cardinality": {"field": "cowrie.session"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}}
                }
            },
            "by_variant": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    "total_commands": {"value_count": {"field": "@timestamp"}}
                }
            },
            "total_unique_commands": {"cardinality": {"field": "json.input"}},
            "timeline": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"},
                "aggs": {
                    "by_variant": {"terms": {"field": "cowrie_variant", "size": 5}}
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    # Process commands
    commands = []
    intent_distribution = {}
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    mitre_techniques = {}
    
    for bucket in aggs.get("commands", {}).get("buckets", []):
        command = bucket["key"]
        classification = classify_command(command)
        
        # Filter by category if specified
        if category and classification["intent"] != category:
            continue
        
        # Track distributions
        intent = classification["intent"]
        intent_distribution[intent] = intent_distribution.get(intent, 0) + bucket["doc_count"]
        risk_distribution[classification["risk"]] += bucket["doc_count"]
        
        if classification["mitre"]:
            mitre_techniques[classification["mitre"]] = mitre_techniques.get(classification["mitre"], 0) + bucket["doc_count"]
        
        # Variant breakdown
        variants = {}
        for v in bucket.get("by_variant", {}).get("buckets", []):
            variants[v["key"]] = v["doc_count"]
        
        # Combine old and new field values
        unique_ips = max(
            bucket.get("unique_ips_old", {}).get("value", 0),
            bucket.get("unique_ips_new", {}).get("value", 0)
        )
        sessions_count = max(
            bucket.get("sessions_old", {}).get("value", 0),
            bucket.get("sessions_new", {}).get("value", 0)
        )
        
        commands.append({
            "command": command,
            "count": bucket["doc_count"],
            "unique_ips": unique_ips,
            "sessions": sessions_count,
            "first_seen": bucket["first_seen"]["value_as_string"],
            "last_seen": bucket["last_seen"]["value_as_string"],
            "intent": classification["intent"],
            "description": classification["description"],
            "mitre": classification["mitre"],
            "risk": classification["risk"],
            "by_variant": variants
        })
    
    # Timeline processing
    timeline = []
    for bucket in aggs.get("timeline", {}).get("buckets", []):
        entry = {"timestamp": bucket["key_as_string"], "total": bucket["doc_count"]}
        for v in bucket.get("by_variant", {}).get("buckets", []):
            entry[v["key"]] = v["doc_count"]
        timeline.append(entry)
    
    # Variant totals
    variant_totals = {}
    for bucket in aggs.get("by_variant", {}).get("buckets", []):
        variant_totals[bucket["key"]] = bucket["total_commands"]["value"]
    
    return {
        "time_range": time_range,
        "total_executions": sum(c["count"] for c in commands),
        "unique_commands": aggs.get("total_unique_commands", {}).get("value", 0),
        "commands": commands,
        "intent_distribution": [
            {"intent": k, "count": v, "description": COMMAND_INTENTS.get(k, {}).get("description", "Unknown")}
            for k, v in sorted(intent_distribution.items(), key=lambda x: -x[1])
        ],
        "risk_distribution": risk_distribution,
        "mitre_techniques": [
            {"technique": k, "count": v}
            for k, v in sorted(mitre_techniques.items(), key=lambda x: -x[1])
        ],
        "variant_totals": variant_totals,
        "timeline": timeline
    }


@router.get("/downloaded-files")
async def get_cowrie_downloaded_files(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Extract downloaded file URLs from Cowrie commands (wget, curl, etc).
    """
    import re
    
    es = get_es_service()
    
    # Search for commands containing download patterns
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"json.eventid": "cowrie.command.input"}},
            {"bool": {"should": [
                {"wildcard": {"json.input.keyword": "*wget*"}},
                {"wildcard": {"json.input.keyword": "*curl*"}},
                {"wildcard": {"json.input.keyword": "*http://*"}},
                {"wildcard": {"json.input.keyword": "*https://*"}},
                {"wildcard": {"json.input.keyword": "*tftp*"}},
                {"wildcard": {"json.input.keyword": "*scp*"}},
                {"wildcard": {"json.input.keyword": "*ftp://*"}},
            ], "minimum_should_match": 1}}
        ]}},
        size=1000,
        sort=[{"@timestamp": "desc"}]
    )
    
    # URL pattern regex
    url_pattern = re.compile(r'(https?://[^\s;"\'<>\|]+|ftp://[^\s;"\'<>\|]+)', re.IGNORECASE)
    
    # Extract URLs
    url_data = {}  # url -> {count, first_seen, sessions, source_ips, commands}
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        command = json_data.get("input", "")
        session = json_data.get("session", "")
        src_ip = json_data.get("src_ip", "")
        timestamp = source.get("@timestamp", "")
        
        # Find URLs in command
        urls = url_pattern.findall(command)
        
        for url in urls:
            # Clean URL
            url = url.rstrip(')')
            
            if url not in url_data:
                url_data[url] = {
                    "url": url,
                    "count": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "sessions": set(),
                    "source_ips": set(),
                    "sample_commands": []
                }
            
            url_data[url]["count"] += 1
            url_data[url]["last_seen"] = timestamp
            url_data[url]["sessions"].add(session)
            url_data[url]["source_ips"].add(src_ip)
            
            if len(url_data[url]["sample_commands"]) < 3:
                url_data[url]["sample_commands"].append(command[:200])
    
    # Convert to list and sort
    urls_list = []
    for url, data in sorted(url_data.items(), key=lambda x: -x[1]["count"]):
        # Categorize URL
        url_lower = url.lower()
        if any(ext in url_lower for ext in ['.sh', '.bash', '.pl', '.py']):
            category = "script"
        elif any(ext in url_lower for ext in ['.exe', '.elf', '.bin', '.dll']):
            category = "executable"
        elif any(ext in url_lower for ext in ['.tar', '.gz', '.zip', '.bz2']):
            category = "archive"
        elif 'pastebin' in url_lower or 'raw.github' in url_lower:
            category = "paste"
        else:
            category = "other"
        
        urls_list.append({
            "url": url,
            "count": data["count"],
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            "session_count": len(data["sessions"]),
            "source_ip_count": len(data["source_ips"]),
            "sample_commands": data["sample_commands"],
            "category": category,
            "domain": url.split('/')[2] if len(url.split('/')) > 2 else url,
        })
    
    # Group by domain
    domain_counts = {}
    for url_info in urls_list:
        domain = url_info["domain"]
        domain_counts[domain] = domain_counts.get(domain, 0) + url_info["count"]
    
    top_domains = [
        {"domain": d, "count": c}
        for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])[:10]
    ]
    
    # Category breakdown
    category_counts = {}
    for url_info in urls_list:
        cat = url_info["category"]
        category_counts[cat] = category_counts.get(cat, 0) + url_info["count"]
    
    return {
        "time_range": time_range,
        "total_urls": len(urls_list),
        "total_download_attempts": sum(u["count"] for u in urls_list),
        "urls": urls_list[:100],  # Top 100 URLs
        "top_domains": top_domains,
        "category_breakdown": category_counts
    }
