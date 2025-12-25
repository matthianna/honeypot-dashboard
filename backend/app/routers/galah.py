"""Galah web honeypot API routes."""

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
    GalahRequest,
    GalahUserAgent,
    GalahPath,
)

router = APIRouter()
INDEX = ".ds-galah-*"


@router.get("/stats", response_model=StatsResponse)
async def get_galah_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Galah honeypot statistics."""
    es = get_es_service()
    
    total_events = await es.get_total_events(INDEX, time_range)
    unique_ips = await es.get_unique_ips(INDEX, time_range)
    
    return StatsResponse(
        total_events=total_events,
        unique_ips=unique_ips,
        time_range=time_range
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_galah_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Galah event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    timeline = await es.get_timeline(INDEX, time_range, interval)
    
    return TimelineResponse(
        data=[TimelinePoint(**point) for point in timeline],
        time_range=time_range
    )


@router.get("/geo", response_model=GeoDistributionResponse)
async def get_galah_geo(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Galah geographic distribution."""
    es = get_es_service()
    
    geo_data = await es.get_geo_distribution(INDEX, time_range)
    
    return GeoDistributionResponse(
        data=[GeoPoint(**point) for point in geo_data],
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_galah_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top Galah attackers."""
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


@router.get("/requests", response_model=List[GalahRequest])
async def get_galah_requests(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get most common HTTP requests."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=limit,
        sort=[{"@timestamp": "desc"}],
        fields=["http.request.method", "url.path", "source.ip", "@timestamp"]
    )
    
    # Aggregate requests
    request_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        method = source.get("http", {}).get("request", {}).get("method", "GET")
        uri = source.get("url", {}).get("path", "/")
        
        key = (method, uri)
        request_counts[key] = request_counts.get(key, 0) + 1
    
    requests = [
        GalahRequest(
            method=key[0],
            uri=key[1],
            count=count
        )
        for key, count in sorted(request_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return requests


@router.get("/user-agents", response_model=List[GalahUserAgent])
async def get_galah_user_agents(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get most common user agents."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"exists": {"field": "user_agent.original"}}
                ]
            }
        },
        size=limit,
        sort=[{"@timestamp": "desc"}],
        fields=["user_agent.original"]
    )
    
    # Aggregate user agents
    ua_counts = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        ua = source.get("user_agent", {}).get("original", "")
        if ua:
            ua_counts[ua] = ua_counts.get(ua, 0) + 1
    
    user_agents = [
        GalahUserAgent(
            user_agent=ua,
            count=count
        )
        for ua, count in sorted(ua_counts.items(), key=lambda x: -x[1])[:limit]
    ]
    
    return user_agents


@router.get("/paths", response_model=List[GalahPath])
async def get_galah_paths(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get most targeted paths."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=limit * 2,
        sort=[{"@timestamp": "desc"}],
        fields=["url.path", "http.request.method"]
    )
    
    # Aggregate paths with their methods
    path_data = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        path = source.get("url", {}).get("path", "/")
        method = source.get("http", {}).get("request", {}).get("method", "GET")
        
        if path not in path_data:
            path_data[path] = {"count": 0, "methods": set()}
        path_data[path]["count"] += 1
        path_data[path]["methods"].add(method)
    
    paths = [
        GalahPath(
            path=path,
            count=data["count"],
            methods=list(data["methods"])
        )
        for path, data in sorted(path_data.items(), key=lambda x: -x[1]["count"])[:limit]
    ]
    
    return paths


@router.get("/interactions")
async def get_galah_interactions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """
    Get Galah HTTP interactions with request/response details.
    This includes AI-generated responses from the LLM honeypot.
    """
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=limit,
        sort=[{"@timestamp": "desc"}]
    )
    
    interactions = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        
        # Check if this interaction has AI-generated response content
        # New format: http.response.body.content
        # Legacy format: httpResponse.body
        has_response_content = bool(
            source.get("http", {}).get("response", {}).get("body", {}).get("content") or
            source.get("httpResponse", {}).get("body")
        )
        
        # Get content type
        content_type = (
            source.get("http", {}).get("response", {}).get("mime_type") or
            source.get("httpResponse", {}).get("headers", {}).get("Content-Type", "")
        )
        
        # Extract relevant fields
        interaction = {
            "id": hit["_id"],
            "timestamp": source.get("@timestamp"),
            "source_ip": source.get("source", {}).get("ip"),
            "source_port": source.get("source", {}).get("port") or source.get("srcPort"),
            "destination_port": source.get("destination", {}).get("port") or source.get("port"),
            "method": source.get("http", {}).get("request", {}).get("method"),
            "path": source.get("url", {}).get("path"),
            "message": source.get("msg"),
            "session_id": source.get("session", {}).get("id"),
            "has_response_content": has_response_content,
            "content_type": content_type,
            "geo": {
                "country": source.get("source", {}).get("geo", {}).get("country_name"),
                "city": source.get("source", {}).get("geo", {}).get("city_name"),
                "location": source.get("source", {}).get("geo", {}).get("location"),
            },
        }
        
        interactions.append(interaction)
    
    return {
        "total": result.get("hits", {}).get("total", {}).get("value", 0),
        "interactions": interactions
    }


@router.get("/logs")
async def get_galah_logs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    src_ip: Optional[str] = Query(default=None),
    path: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get Galah logs with filtering options."""
    es = get_es_service()
    
    filters = {}
    if src_ip:
        filters["source.ip"] = src_ip
    if path:
        filters["url.path"] = path
    
    return await es.get_logs(INDEX, time_range, limit, search, filters)


@router.get("/heatmap")
async def get_galah_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly heatmap data for Galah."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    return {"data": heatmap_data, "time_range": time_range}


@router.get("/ai-analysis")
async def get_galah_ai_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Analyze AI response effectiveness - key metric for thesis.
    Shows how well the LLM honeypot responds to various attack types.
    """
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "response_status": {
                "terms": {"field": "msg", "size": 10}
            },
            "by_method": {
                "terms": {"field": "http.request.method", "size": 10},
                "aggs": {
                    "success": {
                        "filter": {"term": {"msg": "successfulResponse"}}
                    },
                    "failed": {
                        "filter": {"prefix": {"msg": "failedResponse"}}
                    }
                }
            },
            "success_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h" if time_range == "24h" else "6h"
                },
                "aggs": {
                    "success": {
                        "filter": {"term": {"msg": "successfulResponse"}}
                    },
                    "failed": {
                        "filter": {"prefix": {"msg": "failedResponse"}}
                    }
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    # Calculate overall success rate
    total = sum(b["doc_count"] for b in aggs.get("response_status", {}).get("buckets", []))
    success = next((b["doc_count"] for b in aggs.get("response_status", {}).get("buckets", []) 
                   if b["key"] == "successfulResponse"), 0)
    
    return {
        "time_range": time_range,
        "total_requests": total,
        "successful_responses": success,
        "failed_responses": total - success,
        "success_rate": round(success / total * 100, 1) if total > 0 else 0,
        "response_breakdown": [
            {"status": b["key"], "count": b["doc_count"]}
            for b in aggs.get("response_status", {}).get("buckets", [])
        ],
        "by_method": [
            {
                "method": b["key"],
                "total": b["doc_count"],
                "success": b["success"]["doc_count"],
                "failed": b["failed"]["doc_count"],
                "success_rate": round(b["success"]["doc_count"] / b["doc_count"] * 100, 1) if b["doc_count"] > 0 else 0
            }
            for b in aggs.get("by_method", {}).get("buckets", [])
        ],
        "timeline": [
            {
                "timestamp": b["key_as_string"],
                "success": b["success"]["doc_count"],
                "failed": b["failed"]["doc_count"],
                "total": b["doc_count"]
            }
            for b in aggs.get("success_over_time", {}).get("buckets", [])
        ]
    }


@router.get("/attack-patterns")
async def get_galah_attack_patterns(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Categorize and analyze attack patterns detected by Galah.
    Useful for thesis: understanding what attackers are looking for.
    """
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=500,
        sort=[{"@timestamp": "desc"}]
    )
    
    # Categorize attacks based on URL patterns
    attack_categories = {
        "phpunit_exploit": {"pattern": "phpunit", "count": 0, "paths": [], "description": "PHPUnit RCE (CVE-2017-9841)"},
        "router_exploit": {"pattern": ["gpon", "hnap", "boaform", "boafrm"], "count": 0, "paths": [], "description": "Router/IoT Exploitation"},
        "cgi_injection": {"pattern": "cgi-bin", "count": 0, "paths": [], "description": "CGI Command Injection"},
        "path_traversal": {"pattern": ["../", "..%2f", "%2e%2e"], "count": 0, "paths": [], "description": "Path Traversal Attack"},
        "php_injection": {"pattern": ["php://", "allow_url_include", "auto_prepend"], "count": 0, "paths": [], "description": "PHP Code Injection"},
        "credential_scan": {"pattern": ["login", "admin", "password", "wp-login"], "count": 0, "paths": [], "description": "Credential/Admin Scanning"},
        "wordpress": {"pattern": ["wp-", "wordpress", "xmlrpc"], "count": 0, "paths": [], "description": "WordPress Exploitation"},
        "generic_scan": {"pattern": None, "count": 0, "paths": [], "description": "Generic Reconnaissance"},
    }
    
    user_agents = {}
    post_bodies = []
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        path = source.get("url", {}).get("path", "/").lower()
        method = source.get("http", {}).get("request", {}).get("method", "GET")
        
        # Categorize the attack
        categorized = False
        for cat_name, cat_data in attack_categories.items():
            if cat_name == "generic_scan":
                continue
            patterns = cat_data["pattern"]
            if isinstance(patterns, str):
                patterns = [patterns]
            if patterns and any(p in path for p in patterns):
                cat_data["count"] += 1
                if len(cat_data["paths"]) < 5:
                    cat_data["paths"].append(source.get("url", {}).get("path", "/"))
                categorized = True
                break
        
        if not categorized:
            attack_categories["generic_scan"]["count"] += 1
            if len(attack_categories["generic_scan"]["paths"]) < 5:
                attack_categories["generic_scan"]["paths"].append(source.get("url", {}).get("path", "/"))
        
        # Collect User-Agents
        headers = source.get("httpRequest", {}).get("headers", {})
        ua = headers.get("User-Agent", "")
        if ua:
            user_agents[ua] = user_agents.get(ua, 0) + 1
        
        # Collect POST bodies
        if method == "POST":
            body = source.get("httpRequest", {}).get("body", "")
            if body and len(post_bodies) < 20:
                post_bodies.append({
                    "path": source.get("url", {}).get("path", "/"),
                    "body": body[:500],  # Truncate long bodies
                    "timestamp": source.get("@timestamp")
                })
    
    # Sort user agents by count
    sorted_user_agents = sorted(user_agents.items(), key=lambda x: -x[1])[:20]
    
    # Categorize user agents
    ua_categories = {
        "scanners": 0,
        "browsers": 0,
        "bots": 0,
        "curl_wget": 0,
        "other": 0
    }
    
    for ua, count in sorted_user_agents:
        ua_lower = ua.lower()
        if any(s in ua_lower for s in ["scanner", "nikto", "nmap", "masscan", "zgrab"]):
            ua_categories["scanners"] += count
        elif any(b in ua_lower for b in ["mozilla", "chrome", "safari", "firefox"]):
            ua_categories["browsers"] += count
        elif any(b in ua_lower for b in ["bot", "crawler", "spider"]):
            ua_categories["bots"] += count
        elif any(b in ua_lower for b in ["curl", "wget", "python", "go-http"]):
            ua_categories["curl_wget"] += count
        else:
            ua_categories["other"] += count
    
    return {
        "time_range": time_range,
        "attack_categories": [
            {
                "category": name,
                "description": data["description"],
                "count": data["count"],
                "example_paths": data["paths"]
            }
            for name, data in attack_categories.items()
            if data["count"] > 0
        ],
        "user_agents": {
            "top_agents": [{"agent": ua, "count": count} for ua, count in sorted_user_agents],
            "categories": ua_categories
        },
        "post_payloads": post_bodies
    }


@router.get("/exploit-intelligence")
async def get_galah_exploit_intelligence(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Extract exploit intelligence from Galah - useful for threat research.
    Identifies specific CVEs and attack tools being used.
    """
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=500,
        sort=[{"@timestamp": "desc"}]
    )
    
    # Known CVE patterns
    cve_patterns = {
        "CVE-2017-9841": {"pattern": "phpunit", "description": "PHPUnit RCE via eval-stdin.php"},
        "CVE-2018-10561": {"pattern": "gponform", "description": "GPON Router Auth Bypass"},
        "CVE-2014-8361": {"pattern": "hnap1", "description": "Realtek SDK Miniigd UPnP SOAP RCE"},
        "CVE-2017-17215": {"pattern": "huawei", "description": "Huawei Router HG532 RCE"},
        "CVE-2021-41773": {"pattern": [".%2e", "..%2f"], "description": "Apache Path Traversal"},
        "CVE-2018-7600": {"pattern": "drupal", "description": "Drupalgeddon2 RCE"},
    }
    
    detected_cves = {}
    malicious_commands = []
    download_urls = []
    
    import re
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    cmd_pattern = re.compile(r'(wget|curl|busybox|sh|bash|nc|ncat|perl|python|ruby|php)\s')
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        path = source.get("url", {}).get("path", "").lower()
        body = source.get("httpRequest", {}).get("body", "")
        full_text = path + " " + body
        
        # Check for CVEs
        for cve, info in cve_patterns.items():
            patterns = info["pattern"] if isinstance(info["pattern"], list) else [info["pattern"]]
            if any(p in path for p in patterns):
                if cve not in detected_cves:
                    detected_cves[cve] = {
                        "cve": cve,
                        "description": info["description"],
                        "count": 0,
                        "first_seen": source.get("@timestamp"),
                        "source_ips": set()
                    }
                detected_cves[cve]["count"] += 1
                detected_cves[cve]["source_ips"].add(source.get("source", {}).get("ip", ""))
                detected_cves[cve]["last_seen"] = source.get("@timestamp")
        
        # Extract URLs (potential malware downloads)
        urls = url_pattern.findall(full_text)
        for url in urls:
            if url not in [u["url"] for u in download_urls]:
                download_urls.append({
                    "url": url,
                    "context": path[:100],
                    "timestamp": source.get("@timestamp")
                })
        
        # Extract commands
        if cmd_pattern.search(full_text):
            if len(malicious_commands) < 30:
                malicious_commands.append({
                    "path": source.get("url", {}).get("path", "")[:200],
                    "body": body[:200] if body else None,
                    "timestamp": source.get("@timestamp"),
                    "source_ip": source.get("source", {}).get("ip", "")
                })
    
    # Convert sets to lists for JSON serialization
    cve_list = []
    for cve, data in detected_cves.items():
        data["source_ips"] = list(data["source_ips"])[:10]
        data["unique_sources"] = len(data["source_ips"])
        cve_list.append(data)
    
    return {
        "time_range": time_range,
        "detected_cves": sorted(cve_list, key=lambda x: -x["count"]),
        "malicious_commands": malicious_commands[:20],
        "malware_urls": download_urls[:20],
        "summary": {
            "total_cves_detected": len(detected_cves),
            "total_malware_urls": len(download_urls),
            "total_command_injections": len(malicious_commands)
        }
    }


@router.get("/session-analysis")
async def get_galah_session_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Analyze attacker sessions - how attackers interact with the AI honeypot.
    """
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_session": {
                "terms": {"field": "session.id", "size": 100},
                "aggs": {
                    "request_count": {
                        "value_count": {"field": "@timestamp"}
                    },
                    "first_request": {
                        "min": {"field": "@timestamp"}
                    },
                    "last_request": {
                        "max": {"field": "@timestamp"}
                    },
                    "source_ip": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["source.ip", "source.geo.country_name"]
                        }
                    },
                    "methods": {
                        "terms": {"field": "http.request.method", "size": 5}
                    },
                    "paths": {
                        "terms": {"field": "url.path", "size": 10}
                    }
                }
            },
            "requests_per_session": {
                "histogram": {
                    "script": {
                        "source": "doc['session.id'].size() > 0 ? 1 : 0",
                        "lang": "painless"
                    },
                    "interval": 1
                }
            },
            "unique_sessions": {
                "cardinality": {"field": "session.id"}
            },
            "unique_ips": {
                "cardinality": {"field": "source.ip"}
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    # Process sessions
    sessions = []
    for bucket in aggs.get("by_session", {}).get("buckets", []):
        if bucket["request_count"]["value"] > 0:
            source_hit = bucket["source_ip"]["hits"]["hits"][0]["_source"] if bucket["source_ip"]["hits"]["hits"] else {}
            
            # Calculate session duration
            first = bucket["first_request"].get("value_as_string")
            last = bucket["last_request"].get("value_as_string")
            duration = None
            if first and last:
                try:
                    from datetime import datetime
                    first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    duration = (last_dt - first_dt).total_seconds()
                except:
                    pass
            
            sessions.append({
                "session_id": bucket["key"][:20] + "..." if len(bucket["key"]) > 20 else bucket["key"],
                "request_count": bucket["request_count"]["value"],
                "duration_seconds": duration,
                "source_ip": source_hit.get("source", {}).get("ip"),
                "country": source_hit.get("source", {}).get("geo", {}).get("country_name"),
                "methods": [m["key"] for m in bucket["methods"]["buckets"]],
                "top_paths": [p["key"][:50] for p in bucket["paths"]["buckets"][:3]]
            })
    
    # Sort by request count
    sessions = sorted(sessions, key=lambda x: -x["request_count"])
    
    # Calculate session statistics
    request_counts = [s["request_count"] for s in sessions]
    durations = [s["duration_seconds"] for s in sessions if s["duration_seconds"] is not None]
    
    return {
        "time_range": time_range,
        "total_sessions": aggs.get("unique_sessions", {}).get("value", 0),
        "total_unique_ips": aggs.get("unique_ips", {}).get("value", 0),
        "session_stats": {
            "avg_requests_per_session": sum(request_counts) / len(request_counts) if request_counts else 0,
            "max_requests_in_session": max(request_counts) if request_counts else 0,
            "avg_session_duration": sum(durations) / len(durations) if durations else 0,
            "max_session_duration": max(durations) if durations else 0,
        },
        "top_sessions": sessions[:20],
        "single_request_sessions": len([s for s in sessions if s["request_count"] == 1]),
        "multi_request_sessions": len([s for s in sessions if s["request_count"] > 1]),
    }


@router.get("/interaction/{interaction_id}/preview")
async def get_galah_interaction_preview(
    interaction_id: str,
    _: str = Depends(get_current_user)
):
    """
    Get the AI-generated page preview for a specific interaction.
    Returns the HTTP response that was shown to the attacker.
    """
    es = get_es_service()
    
    doc = await es.get_raw_document(INDEX, interaction_id)
    
    if not doc:
        return {"error": "Interaction not found"}
    
    # Extract response data - check both new and legacy fields
    # New format: http.response.body.content
    # Legacy format: httpResponse.body
    http_response_new = doc.get("http", {}).get("response", {})
    http_response_legacy = doc.get("httpResponse", {})
    galah_data = doc.get("galah", {})
    
    # Get the response body (this is what the attacker saw)
    # Try new field first, then fall back to legacy
    response_body = http_response_new.get("body", {}).get("content", "")
    if not response_body:
        response_body = http_response_legacy.get("body", "")
    
    # Get response headers and status
    response_headers = http_response_legacy.get("headers", {})
    status_code = http_response_legacy.get("statusCode", 200)
    content_type = http_response_new.get("mime_type", response_headers.get("Content-Type", "text/html"))
    
    # Get request details for context
    http_request = doc.get("httpRequest", {})
    request_path = doc.get("url", {}).get("path", "/")
    request_method = doc.get("http", {}).get("request", {}).get("method", "GET")
    
    # Check if we have response content
    has_response = bool(response_body)
    
    return {
        "id": interaction_id,
        "timestamp": doc.get("@timestamp"),
        "source_ip": doc.get("source", {}).get("ip"),
        "source_geo": doc.get("source", {}).get("geo", {}),
        "request": {
            "method": request_method,
            "path": request_path,
            "headers": http_request.get("headers", {}),
            "body": http_request.get("body", ""),
        },
        "response": {
            "status_code": status_code,
            "headers": response_headers,
            "body": response_body,
            "content_type": content_type,
            "has_content": has_response,
        },
        "galah_metadata": galah_data,
        "msg": doc.get("msg"),
        "session_id": doc.get("session", {}).get("id"),
    }


@router.get("/success-rate-trend")
async def get_galah_success_rate_trend(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get AI response success rate over time - key thesis metric."""
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
                    "success": {
                        "filter": {"term": {"msg.keyword": "success"}}
                    },
                    "failed": {
                        "filter": {"term": {"msg.keyword": "failed"}}
                    }
                }
            }
        }
    )
    
    trend_data = []
    for bucket in result.get("aggregations", {}).get("over_time", {}).get("buckets", []):
        success = bucket.get("success", {}).get("doc_count", 0)
        failed = bucket.get("failed", {}).get("doc_count", 0)
        total = success + failed
        trend_data.append({
            "timestamp": bucket["key_as_string"],
            "success": success,
            "failed": failed,
            "total": total,
            "success_rate": round(success / total * 100, 1) if total > 0 else 0
        })
    
    return {"time_range": time_range, "trend": trend_data}


@router.get("/path-categories")
async def get_galah_path_categories(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Categorize attacked paths into meaningful categories."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "paths": {
                "terms": {"field": "url.path.keyword", "size": 200}
            }
        }
    )
    
    # Categorize paths
    categories = {
        "Admin/Config": ["/admin", "/wp-admin", "/administrator", "/config", "/phpmyadmin", "/cpanel"],
        "Login/Auth": ["/login", "/signin", "/auth", "/user", "/account", "/register"],
        "API/Data": ["/api", "/graphql", "/rest", "/json", "/xml", "/data"],
        "CMS/Plugins": ["/wp-", "/joomla", "/drupal", "/plugin", "/module", "/component"],
        "Shell/Exploit": ["/shell", "/cmd", "/eval", "/exec", ".php", ".asp", ".cgi"],
        "Sensitive Files": ["/.env", "/.git", "/config", "/backup", "/.htaccess", "/passwd"],
        "Scanning": ["/robots.txt", "/sitemap", "/favicon", "/well-known", "/ads.txt"],
    }
    
    category_counts = {cat: 0 for cat in categories}
    category_counts["Other"] = 0
    path_details = {cat: [] for cat in categories}
    path_details["Other"] = []
    
    for bucket in result.get("aggregations", {}).get("paths", {}).get("buckets", []):
        path = bucket["key"].lower()
        count = bucket["doc_count"]
        categorized = False
        
        for cat, patterns in categories.items():
            if any(p in path for p in patterns):
                category_counts[cat] += count
                if len(path_details[cat]) < 5:
                    path_details[cat].append({"path": bucket["key"], "count": count})
                categorized = True
                break
        
        if not categorized:
            category_counts["Other"] += count
            if len(path_details["Other"]) < 5:
                path_details["Other"].append({"path": bucket["key"], "count": count})
    
    categories_list = [
        {"category": cat, "count": count, "top_paths": path_details[cat]}
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1])
        if count > 0
    ]
    
    return {"time_range": time_range, "categories": categories_list}


@router.get("/request-methods")
async def get_galah_request_methods(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get request method distribution with success rates."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_method": {
                "terms": {"field": "http.request.method.keyword", "size": 10},
                "aggs": {
                    "success": {"filter": {"term": {"msg.keyword": "success"}}},
                    "failed": {"filter": {"term": {"msg.keyword": "failed"}}}
                }
            }
        }
    )
    
    methods = []
    for bucket in result.get("aggregations", {}).get("by_method", {}).get("buckets", []):
        success = bucket.get("success", {}).get("doc_count", 0)
        failed = bucket.get("failed", {}).get("doc_count", 0)
        total = bucket["doc_count"]
        methods.append({
            "method": bucket["key"],
            "count": total,
            "success": success,
            "failed": failed,
            "success_rate": round(success / total * 100, 1) if total > 0 else 0
        })
    
    return {"time_range": time_range, "methods": methods}


@router.get("/session-depth")
async def get_galah_session_depth(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Analyze session depth - how many requests per session."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "sessions": {
                "terms": {"field": "session.id.keyword", "size": 1000},
                "aggs": {
                    "request_count": {"value_count": {"field": "@timestamp"}}
                }
            },
            "total_sessions": {"cardinality": {"field": "session.id.keyword"}}
        }
    )
    
    # Bucket sessions by depth
    depth_buckets = {"1": 0, "2-3": 0, "4-5": 0, "6-10": 0, "11+": 0}
    
    for session in result.get("aggregations", {}).get("sessions", {}).get("buckets", []):
        count = session.get("request_count", {}).get("value", 1)
        if count == 1:
            depth_buckets["1"] += 1
        elif count <= 3:
            depth_buckets["2-3"] += 1
        elif count <= 5:
            depth_buckets["4-5"] += 1
        elif count <= 10:
            depth_buckets["6-10"] += 1
        else:
            depth_buckets["11+"] += 1
    
    distribution = [{"depth": k, "count": v} for k, v in depth_buckets.items()]
    
    return {
        "time_range": time_range,
        "distribution": distribution,
        "total_sessions": result.get("aggregations", {}).get("total_sessions", {}).get("value", 0)
    }


@router.get("/content-types")
async def get_galah_content_types(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get content types served by AI responses."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "content_types": {
                "terms": {"field": "http.response.mime_type.keyword", "size": 20}
            }
        }
    )
    
    content_types = []
    for bucket in result.get("aggregations", {}).get("content_types", {}).get("buckets", []):
        content_types.append({
            "mime_type": bucket["key"],
            "count": bucket["doc_count"]
        })
    
    return {"time_range": time_range, "content_types": content_types}


@router.get("/user-agent-analysis")
async def get_galah_user_agent_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get detailed user agent analysis including browser, OS, and bot detection."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "browsers": {
                "terms": {"field": "user_agent.name.keyword", "size": 15, "missing": "Unknown"}
            },
            "os": {
                "terms": {"field": "user_agent.os.name.keyword", "size": 15, "missing": "Unknown"}
            },
            "devices": {
                "terms": {"field": "user_agent.device.name.keyword", "size": 10, "missing": "Unknown"}
            },
            "raw_agents": {
                "terms": {"field": "user_agent.original.keyword", "size": 30}
            },
            "total": {"value_count": {"field": "@timestamp"}}
        }
    )
    
    # Detect bots based on user agent patterns
    bot_patterns = [
        "bot", "crawler", "spider", "scan", "curl", "wget", "python", "go-http",
        "masscan", "nmap", "zgrab", "nuclei", "nikto", "sqlmap", "dirbuster"
    ]
    
    raw_agents = result.get("aggregations", {}).get("raw_agents", {}).get("buckets", [])
    bot_count = 0
    human_count = 0
    bot_tools = {}
    
    for bucket in raw_agents:
        ua = bucket["key"].lower()
        count = bucket["doc_count"]
        is_bot = False
        
        for pattern in bot_patterns:
            if pattern in ua:
                is_bot = True
                # Identify the tool
                for tool in ["curl", "wget", "python-requests", "go-http", "masscan", 
                            "nmap", "zgrab", "nuclei", "nikto", "sqlmap", "dirbuster"]:
                    if tool in ua:
                        bot_tools[tool] = bot_tools.get(tool, 0) + count
                        break
                else:
                    bot_tools["other_bot"] = bot_tools.get("other_bot", 0) + count
                break
        
        if is_bot:
            bot_count += count
        else:
            human_count += count
    
    browsers = [{"name": b["key"], "count": b["doc_count"]} for b in result.get("aggregations", {}).get("browsers", {}).get("buckets", [])]
    operating_systems = [{"name": b["key"], "count": b["doc_count"]} for b in result.get("aggregations", {}).get("os", {}).get("buckets", [])]
    devices = [{"name": b["key"], "count": b["doc_count"]} for b in result.get("aggregations", {}).get("devices", {}).get("buckets", [])]
    bot_tools_list = [{"tool": k, "count": v} for k, v in sorted(bot_tools.items(), key=lambda x: -x[1])]
    
    total = result.get("aggregations", {}).get("total", {}).get("value", 0)
    
    return {
        "time_range": time_range,
        "browsers": browsers,
        "operating_systems": operating_systems,
        "devices": devices,
        "bot_detection": {
            "bot_count": bot_count,
            "human_count": human_count,
            "bot_percentage": round(bot_count / total * 100, 1) if total > 0 else 0,
            "tools": bot_tools_list,
        },
        "total_requests": total
    }


@router.get("/http-fingerprints")
async def get_galah_http_fingerprints(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get HTTP client fingerprinting based on header patterns."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "header_hashes": {
                "terms": {"field": "httpRequest.headersSortedSha256.keyword", "size": 50}
            },
            "protocol_versions": {
                "terms": {"field": "httpRequest.protocolVersion.keyword", "size": 10}
            },
            "header_patterns": {
                "terms": {"field": "httpRequest.headersSorted.keyword", "size": 30}
            },
            "unique_fingerprints": {
                "cardinality": {"field": "httpRequest.headersSortedSha256.keyword"}
            }
        }
    )
    
    fingerprints = []
    for bucket in result.get("aggregations", {}).get("header_hashes", {}).get("buckets", []):
        fingerprints.append({
            "hash": bucket["key"][:16] + "...",
            "full_hash": bucket["key"],
            "count": bucket["doc_count"]
        })
    
    protocol_versions = [{"version": b["key"], "count": b["doc_count"]} for b in result.get("aggregations", {}).get("protocol_versions", {}).get("buckets", [])]
    
    # Analyze header patterns to identify scanner types
    header_patterns = []
    for bucket in result.get("aggregations", {}).get("header_patterns", {}).get("buckets", []):
        pattern = bucket["key"]
        headers = pattern.split(",")
        scanner_type = "Unknown"
        
        # Identify scanner type by header pattern
        if "Accept-Language" not in headers and "Cookie" not in headers:
            scanner_type = "Automated Scanner"
        elif len(headers) <= 3:
            scanner_type = "Minimal Client"
        elif "Accept-Encoding" in headers and "Accept-Language" in headers:
            scanner_type = "Browser-like"
        else:
            scanner_type = "Mixed"
        
        header_patterns.append({
            "pattern": pattern,
            "header_count": len(headers),
            "count": bucket["doc_count"],
            "scanner_type": scanner_type
        })
    
    return {
        "time_range": time_range,
        "fingerprints": fingerprints,
        "protocol_versions": protocol_versions,
        "header_patterns": header_patterns[:20],
        "unique_fingerprints": result.get("aggregations", {}).get("unique_fingerprints", {}).get("value", 0)
    }


@router.get("/llm-stats")
async def get_galah_llm_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get LLM usage statistics - cache vs fresh generation."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "generation_source": {
                "terms": {"field": "responseMetadata.generationSource.keyword", "size": 10}
            },
            "providers": {
                "terms": {"field": "responseMetadata.info.provider.keyword", "size": 10}
            },
            "models": {
                "terms": {"field": "responseMetadata.info.model.keyword", "size": 10}
            },
            "llm_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h"
                },
                "aggs": {
                    "by_source": {
                        "terms": {"field": "responseMetadata.generationSource.keyword", "size": 5}
                    }
                }
            }
        }
    )
    
    # Parse generation sources
    sources = {}
    for bucket in result.get("aggregations", {}).get("generation_source", {}).get("buckets", []):
        sources[bucket["key"]] = bucket["doc_count"]
    
    llm_count = sources.get("llm", 0)
    cache_count = sources.get("cache", 0)
    total = llm_count + cache_count
    
    providers = [{"provider": b["key"], "count": b["doc_count"]} for b in result.get("aggregations", {}).get("providers", {}).get("buckets", [])]
    models = [{"model": b["key"], "count": b["doc_count"]} for b in result.get("aggregations", {}).get("models", {}).get("buckets", [])]
    
    # Timeline data
    timeline = []
    for bucket in result.get("aggregations", {}).get("llm_over_time", {}).get("buckets", []):
        entry = {"timestamp": bucket["key_as_string"], "llm": 0, "cache": 0}
        for source in bucket.get("by_source", {}).get("buckets", []):
            if source["key"] in entry:
                entry[source["key"]] = source["doc_count"]
        timeline.append(entry)
    
    return {
        "time_range": time_range,
        "summary": {
            "total_responses": total,
            "llm_generated": llm_count,
            "cache_served": cache_count,
            "llm_percentage": round(llm_count / total * 100, 1) if total > 0 else 0,
            "cache_hit_rate": round(cache_count / total * 100, 1) if total > 0 else 0,
        },
        "providers": providers,
        "models": models,
        "timeline": timeline[-48:] if len(timeline) > 48 else timeline  # Last 48 hours
    }
