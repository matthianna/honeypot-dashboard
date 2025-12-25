"""Cowrie honeypot API routes."""

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
    CowrieSession,
    CowrieCredential,
    CowrieCommand,
    CowrieHassh,
    CowrieVariantStats,
)

router = APIRouter()
INDEX = ".ds-cowrie-*"


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
    _: str = Depends(get_current_user)
):
    """Get Cowrie sessions with duration and command count."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "sessions": {
                "terms": {
                    "field": "cowrie.session",
                    "size": limit
                },
                "aggs": {
                    "src_ip": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["cowrie.src_ip", "cowrie.geo.country_name", "cowrie_variant"]
                        }
                    },
                    "start_time": {
                        "min": {"field": "@timestamp"}
                    },
                    "end_time": {
                        "max": {"field": "@timestamp"}
                    },
                    "commands": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.command.input"}
                        }
                    },
                    "login_success": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.login.success"}
                        }
                    }
                }
            }
        }
    )
    
    sessions = []
    for bucket in result.get("aggregations", {}).get("sessions", {}).get("buckets", []):
        hit = bucket["src_ip"]["hits"]["hits"][0]["_source"] if bucket["src_ip"]["hits"]["hits"] else {}
        cowrie_data = hit.get("cowrie", {})
        
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
        
        sessions.append(CowrieSession(
            session_id=bucket["key"],
            src_ip=cowrie_data.get("src_ip", "unknown"),
            start_time=start or "",
            end_time=end,
            duration=duration,
            commands_count=bucket["commands"]["doc_count"],
            country=cowrie_data.get("geo", {}).get("country_name"),
            sensor=cowrie_data.get("sensor")
        ))
    
    return sessions


@router.get("/credentials", response_model=List[CowrieCredential])
async def get_cowrie_credentials(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    variant: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get most common credential attempts."""
    es = get_es_service()
    
    # Build query for login events
    must_clauses = [
        es._get_time_range_query(time_range),
        {
            "bool": {
                "should": [
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
    
    # Aggregate credentials manually - check both cowrie.* and json.* fields
    cred_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        cowrie = source.get("cowrie", {})
        json_data = source.get("json", {})
        
        # Username/password can be in cowrie.* or json.*
        username = cowrie.get("username") or json_data.get("username", "")
        password = cowrie.get("password") or json_data.get("password", "")
        success = cowrie.get("eventid") == "cowrie.login.success"
        
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
    
    must_clauses = [
        es._get_time_range_query(time_range),
        {"term": {"cowrie.eventid": "cowrie.command.input"}}
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
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    {"term": {"cowrie.session": session_id}},
                    {"term": {"cowrie.eventid": "cowrie.command.input"}}
                ]
            }
        },
        size=200,
        sort=[{"@timestamp": "asc"}]
    )
    
    commands = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        command = json_data.get("input", "")
        timestamp = source.get("@timestamp", "")
        
        if command:
            commands.append({
                "command": command,
                "timestamp": timestamp
            })
    
    return {"session_id": session_id, "commands": commands, "total": len(commands)}


@router.get("/session/{session_id}/details")
async def get_session_details(
    session_id: str,
    _: str = Depends(get_current_user)
):
    """Get full session details including all events."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={"term": {"cowrie.session": session_id}},
        size=500,
        sort=[{"@timestamp": "asc"}]
    )
    
    events = []
    session_info = {}
    commands = []
    credentials = []
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        cowrie = source.get("cowrie", {})
        json_data = source.get("json", {})
        event_id = cowrie.get("eventid", "")
        timestamp = source.get("@timestamp", "")
        
        event = {
            "type": event_id,
            "timestamp": timestamp,
            "details": {}
        }
        
        # Extract session info from first connect event
        if event_id == "cowrie.session.connect" and not session_info:
            session_info = {
                "src_ip": cowrie.get("src_ip"),
                "country": cowrie.get("geo", {}).get("country_name"),
                "city": cowrie.get("geo", {}).get("city_name"),
                "sensor": cowrie.get("sensor"),
                "protocol": json_data.get("protocol"),
                "start_time": timestamp
            }
        
        # Extract session duration from closed event
        if event_id == "cowrie.session.closed":
            session_info["end_time"] = timestamp
            duration = json_data.get("duration")
            if duration:
                session_info["duration"] = duration
        
        # Extract commands
        if event_id == "cowrie.command.input":
            cmd = json_data.get("input", "")
            if cmd:
                commands.append({"command": cmd, "timestamp": timestamp})
                event["details"]["command"] = cmd
        
        # Extract login attempts
        if event_id in ["cowrie.login.success", "cowrie.login.failed"]:
            username = json_data.get("username", "")
            password = json_data.get("password", "")
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
            event["details"]["url"] = json_data.get("url", "")
            event["details"]["sha256"] = json_data.get("sha256", "")
        
        # Extract client info
        if event_id == "cowrie.client.version":
            event["details"]["version"] = json_data.get("version", "")
            session_info["client_version"] = json_data.get("version", "")
        
        events.append(event)
    
    return {
        "session_id": session_id,
        "info": session_info,
        "commands": commands,
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
                    {"term": {"cowrie.eventid": "cowrie.client.kex"}}
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
        cowrie = source.get("cowrie", {})
        hassh = cowrie.get("hassh", "")
        version = cowrie.get("version", "")
        
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
    Compare Cowrie variants (plain, LLM, OpenAI) with comprehensive metrics.
    Uses cowrie_variant field which can be: plain, llm, openai
    """
    es = get_es_service()
    
    # Aggregate by cowrie_variant field (top-level field: plain, llm, openai)
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "variants": {
                "terms": {
                    "field": "cowrie_variant",  # plain, llm, openai
                    "size": 10
                },
                "aggs": {
                    "unique_ips": {
                        "cardinality": {"field": "cowrie.src_ip"}
                    },
                    "sessions": {
                        "cardinality": {"field": "cowrie.session"}
                    },
                    "commands": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.command.input"}
                        }
                    },
                    "login_success": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.login.success"}
                        }
                    },
                    "login_failed": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.login.failed"}
                        }
                    },
                    "file_downloads": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.session.file_download"}
                        }
                    },
                    "avg_duration": {
                        "filter": {
                            "term": {"cowrie.eventid": "cowrie.session.closed"}
                        },
                        "aggs": {
                            "duration": {
                                "avg": {"field": "cowrie.duration_seconds"}
                            }
                        }
                    }
                }
            }
        }
    )
    
    variants = []
    for bucket in result.get("aggregations", {}).get("variants", {}).get("buckets", []):
        # Calculate login success rate
        login_success = bucket["login_success"]["doc_count"]
        login_failed = bucket["login_failed"]["doc_count"]
        total_logins = login_success + login_failed
        success_rate = (login_success / total_logins * 100) if total_logins > 0 else 0
        
        # Get average duration
        avg_duration = bucket["avg_duration"]["duration"]["value"]
        
        # Determine variant display name
        variant_key = bucket["key"]
        variant_display_names = {
            "plain": "Plain (Standard)",
            "llm": "LLM (AI-Enhanced)",
            "openai": "OpenAI (GPT-4)"
        }
        display_name = variant_display_names.get(variant_key, variant_key.title())
        
        variants.append({
            "variant": variant_key,
            "display_name": display_name,
            "total_events": bucket["doc_count"],
            "unique_ips": bucket["unique_ips"]["value"],
            "sessions_count": bucket["sessions"]["value"],
            "commands_count": bucket["commands"]["doc_count"],
            "login_success": login_success,
            "login_failed": login_failed,
            "success_rate": round(success_rate, 1),
            "file_downloads": bucket["file_downloads"]["doc_count"],
            "avg_session_duration": round(avg_duration, 2) if avg_duration else None,
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
    
    # Query for specific variant
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
                "terms": {"field": "cowrie.eventid", "size": 20}
            },
            "top_commands": {
                "filter": {"term": {"cowrie.eventid": "cowrie.command.input"}},
                "aggs": {
                    "commands": {
                        "terms": {"field": "json.input", "size": 10}
                    }
                }
            },
            "top_countries": {
                "terms": {"field": "cowrie.geo.country_name", "size": 10}
            },
            "duration_histogram": {
                "filter": {"term": {"cowrie.eventid": "cowrie.session.closed"}},
                "aggs": {
                    "durations": {
                        "histogram": {
                            "field": "cowrie.duration_seconds",
                            "interval": 10,
                            "min_doc_count": 1
                        }
                    }
                }
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
        "duration_distribution": [
            {"duration_range": f"{int(b['key'])}-{int(b['key'])+10}s", "count": b["doc_count"]}
            for b in aggs.get("duration_histogram", {}).get("durations", {}).get("buckets", [])
        ],
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
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_variant": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    # Session metrics
                    "session_count": {
                        "cardinality": {"field": "cowrie.session"}
                    },
                    "unique_ips": {
                        "cardinality": {"field": "cowrie.src_ip"}
                    },
                    # Duration stats
                    "session_closed": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.session.closed"}},
                        "aggs": {
                            "avg_duration": {"avg": {"field": "cowrie.duration_seconds"}},
                            "max_duration": {"max": {"field": "cowrie.duration_seconds"}},
                            "percentiles": {
                                "percentiles": {
                                    "field": "cowrie.duration_seconds",
                                    "percents": [50, 90, 99]
                                }
                            }
                        }
                    },
                    # Login metrics
                    "login_success": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.login.success"}}
                    },
                    "login_failed": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.login.failed"}}
                    },
                    # Command metrics
                    "commands": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.command.input"}},
                        "aggs": {
                            "unique_commands": {
                                "cardinality": {"field": "json.input"}
                            }
                        }
                    },
                    # Downloads
                    "downloads": {
                        "filter": {"term": {"cowrie.eventid": "cowrie.session.file_download"}}
                    },
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
        session_closed = bucket.get("session_closed", {})
        percentiles = session_closed.get("percentiles", {}).get("values", {})
        
        login_success = bucket["login_success"]["doc_count"]
        login_failed = bucket["login_failed"]["doc_count"]
        total_logins = login_success + login_failed
        
        commands_data = bucket.get("commands", {})
        
        variant_key = bucket["key"]
        variant_display_names = {
            "plain": "Plain (Standard)",
            "llm": "LLM (AI-Enhanced)",
            "openai": "OpenAI (GPT-4)"
        }
        comparison.append({
            "variant": variant_key,
            "display_name": variant_display_names.get(variant_key, variant_key.title()),
            "metrics": {
                "total_events": bucket["doc_count"],
                "unique_ips": bucket["unique_ips"]["value"],
                "sessions": bucket["session_count"]["value"],
                "login_success": login_success,
                "login_failed": login_failed,
                "login_success_rate": round(login_success / total_logins * 100, 1) if total_logins > 0 else 0,
                "commands_executed": commands_data["doc_count"],
                "unique_commands": commands_data.get("unique_commands", {}).get("value", 0),
                "file_downloads": bucket["downloads"]["doc_count"],
            },
            "duration": {
                "avg": round(session_closed.get("avg_duration", {}).get("value") or 0, 2),
                "max": round(session_closed.get("max_duration", {}).get("value") or 0, 2),
                "p50": round(percentiles.get("50.0") or 0, 2),
                "p90": round(percentiles.get("90.0") or 0, 2),
                "p99": round(percentiles.get("99.0") or 0, 2),
            },
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
        filters["cowrie.eventid"] = event_type
    if session_id:
        filters["cowrie.session"] = session_id
    if src_ip:
        filters["cowrie.src_ip"] = src_ip
    
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
            {"terms": {"cowrie.eventid.keyword": ["cowrie.login.failed", "cowrie.login.success"]}}
        ]}},
        size=0,
        aggs={
            "by_sensor": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    "by_result": {
                        "terms": {"field": "cowrie.eventid.keyword", "size": 10}
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
    """Get session duration distribution."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"exists": {"field": "cowrie.duration"}}
        ]}},
        size=0,
        aggs={
            "duration_ranges": {
                "range": {
                    "field": "cowrie.duration",
                    "ranges": [
                        {"key": "0-10s", "to": 10},
                        {"key": "10-30s", "from": 10, "to": 30},
                        {"key": "30s-1m", "from": 30, "to": 60},
                        {"key": "1-5m", "from": 60, "to": 300},
                        {"key": "5-15m", "from": 300, "to": 900},
                        {"key": "15m+", "from": 900}
                    ]
                }
            },
            "avg_duration": {"avg": {"field": "cowrie.duration"}},
            "max_duration": {"max": {"field": "cowrie.duration"}},
            "percentiles": {"percentiles": {"field": "cowrie.duration", "percents": [50, 75, 90, 95]}}
        }
    )
    
    ranges = []
    for bucket in result.get("aggregations", {}).get("duration_ranges", {}).get("buckets", []):
        ranges.append({
            "range": bucket["key"],
            "count": bucket["doc_count"]
        })
    
    stats = {
        "avg_duration": round(result.get("aggregations", {}).get("avg_duration", {}).get("value", 0) or 0, 1),
        "max_duration": round(result.get("aggregations", {}).get("max_duration", {}).get("value", 0) or 0, 1),
        "percentiles": result.get("aggregations", {}).get("percentiles", {}).get("values", {})
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
                "terms": {"field": "cowrie.eventid.keyword", "size": 50}
            },
            "unique_sessions": {
                "cardinality": {"field": "cowrie.session.keyword"}
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
                "terms": {"field": "cowrie.password.keyword", "size": 15, "min_doc_count": 2}
            },
            "json_passwords": {
                "terms": {"field": "json.password.keyword", "size": 15, "min_doc_count": 2}
            },
            "top_usernames": {
                "terms": {"field": "cowrie.username.keyword", "size": 15, "min_doc_count": 2}
            },
            "json_usernames": {
                "terms": {"field": "json.username.keyword", "size": 15, "min_doc_count": 2}
            },
            "unique_ips_with_creds": {
                "cardinality": {"field": "cowrie.src_ip.keyword"}
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
            {"term": {"cowrie.eventid.keyword": "cowrie.client.version"}}
        ]}},
        size=0,
        aggs={
            "ssh_versions": {
                "terms": {"field": "json.version.keyword", "size": 50}
            },
            "hassh_fingerprints": {
                "terms": {"field": "json.hassh.keyword", "size": 30}
            },
            "unique_clients": {
                "cardinality": {"field": "json.hassh.keyword"}
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
            {"term": {"cowrie.eventid.keyword": "cowrie.client.kex"}}
        ]}},
        size=1000,
        fields=["json.encCS", "json.kexAlgs", "json.macCS", "cowrie.src_ip", "@timestamp"]
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
            src_ip = src.get("cowrie", {}).get("src_ip")
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
    
    # Get commands
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"exists": {"field": "json.input"}}
        ]}},
        size=0,
        aggs={
            "commands": {
                "terms": {"field": "json.input.keyword", "size": 200}
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
    
    # Get all commands with context
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"cowrie.eventid": "cowrie.command.input"}}
        ]}},
        size=0,
        aggs={
            "commands": {
                "terms": {"field": "json.input.keyword", "size": 200},
                "aggs": {
                    "by_variant": {"terms": {"field": "cowrie_variant", "size": 10}},
                    "unique_ips": {"cardinality": {"field": "cowrie.src_ip"}},
                    "sessions": {"cardinality": {"field": "cowrie.session"}},
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
            "total_unique_commands": {"cardinality": {"field": "json.input.keyword"}},
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
        
        commands.append({
            "command": command,
            "count": bucket["doc_count"],
            "unique_ips": bucket["unique_ips"]["value"],
            "sessions": bucket["sessions"]["value"],
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
