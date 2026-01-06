"""Analytics API routes - Comprehensive analytics dashboard endpoints."""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service

router = APIRouter()

# Index patterns
INDICES = {
    "cowrie": ".ds-cowrie-*",
    "dionaea": "dionaea-*",
    "galah": ".ds-galah-*",
    "rdpy": ".ds-rdpy-*",
    "heralding": ".ds-heralding-*",
    "firewall": ".ds-filebeat-*",
}

# Field mappings per honeypot
IP_FIELDS = {
    "cowrie": "json.src_ip",
    "dionaea": "source.ip.keyword",
    "galah": "source.ip",
    "rdpy": "source.ip",
    "heralding": "source.ip",
    "firewall": "fw.src_ip",  # Firewall uses fw.* fields
}

GEO_FIELDS = {
    "cowrie": "source.geo.country_name",
    "dionaea": "source.geo.country_name",
    "galah": "source.geo.country_name",
    "rdpy": "source.geo.country_name",
    "heralding": "source.geo.country_name",
    "firewall": "source.geo.country_name",
}

# Firewall logs have a 1-hour offset (stored in local time but marked as UTC)
FIREWALL_TIMEZONE_OFFSET_HOURS = 1


def get_firewall_time_range_query(time_range: str) -> dict:
    """
    Get time range query adjusted for firewall's 1-hour timestamp offset.
    
    Firewall logs are stored with timestamps 1 hour behind actual time.
    To query "last 1 hour" of actual events, we need to look for timestamps
    from 2 hours ago to 1 hour ago.
    """
    time_ranges = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    
    delta = time_ranges.get(time_range, timedelta(hours=24))
    now = datetime.utcnow()
    
    # Shift the time window back by 1 hour to account for offset
    offset = timedelta(hours=FIREWALL_TIMEZONE_OFFSET_HOURS)
    
    return {
        "range": {
            "@timestamp": {
                "gte": (now - delta - offset).isoformat() + "Z",
                "lte": now.isoformat() + "Z"
            }
        }
    }


def build_firewall_filter_query(
    time_range: str,
    direction: str = "all",
    src_ip: Optional[str] = None,
    country: Optional[str] = None,
    dst_port: Optional[int] = None,
) -> Dict[str, Any]:
    """Build Elasticsearch query for firewall with timezone offset adjustment."""
    must_clauses = [get_firewall_time_range_query(time_range)]
    
    if direction != "all":
        must_clauses.append({"term": {"fw.dir": direction}})
    
    if src_ip:
        must_clauses.append({"term": {"fw.src_ip": src_ip}})
    
    if country:
        must_clauses.append({"term": {"source.geo.country_name": country}})
    
    if dst_port:
        must_clauses.append({"term": {"fw.dst_port": dst_port}})
    
    return {"bool": {"must": must_clauses}}


def build_filter_query(
    time_range: str,
    honeypot: Optional[str] = None,
    protocol: Optional[str] = None,
    country: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    ai_variant: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build Elasticsearch query with global filters."""
    es = get_es_service()
    must_clauses = [es._get_time_range_query(time_range)]
    
    if src_ip:
        must_clauses.append({"multi_match": {"query": src_ip, "fields": ["source.ip", "json.src_ip"]}})
    
    if country:
        must_clauses.append({"multi_match": {"query": country, "fields": ["source.geo.country_name", "geoip.country_name"]}})
    
    if dst_port:
        must_clauses.append({"term": {"destination.port": dst_port}})
    
    if ai_variant:
        must_clauses.append({"term": {"cowrie_variant": ai_variant}})
    
    if session_id:
        must_clauses.append({"multi_match": {"query": session_id, "fields": ["json.session", "session.id", "session_id"]}})
    
    if protocol:
        must_clauses.append({"multi_match": {"query": protocol.lower(), "fields": ["network.protocol", "json.protocol"]}})
    
    return {"bool": {"must": must_clauses}}


# ==================== OVERVIEW ENDPOINTS ====================

@router.get("/overview")
async def get_analytics_overview(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    honeypot: Optional[str] = None,
    protocol: Optional[str] = None,
    country: Optional[str] = None,
    src_ip: Optional[str] = None,
    ai_variant: Optional[str] = None,
    _: str = Depends(get_current_user)
):
    """Get executive overview with KPIs."""
    es = get_es_service()
    start_time = datetime.now()
    
    # Determine which indices to query
    indices_to_query = [INDICES[honeypot]] if honeypot and honeypot in INDICES else list(INDICES.values())
    
    kpis = {
        "total_events": 0,
        "total_sessions": 0,
        "unique_ips": 0,
        "auth_attempts": 0,
        "successful_logins": 0,
        "web_requests": 0,
        "malware_captures": 0,
    }
    
    honeypot_breakdown = {}
    
    for hp_name, index in INDICES.items():
        if honeypot and hp_name != honeypot:
            continue
        
        try:
            # Use firewall-specific query for firewall index (with 1h timezone offset)
            if hp_name == "firewall":
                query = build_firewall_filter_query(time_range, direction="in", src_ip=src_ip, country=country)
            else:
                query = build_filter_query(time_range, honeypot=hp_name, protocol=protocol, country=country, src_ip=src_ip, ai_variant=ai_variant)
            
            # For Cowrie, support both old (json.src_ip) and new (cowrie.src_ip) field structures
            if hp_name == "cowrie":
                aggs = {
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}},
                }
            else:
                aggs = {
                    "unique_ips": {"cardinality": {"field": IP_FIELDS.get(hp_name, "source.ip")}},
                }
            
            # Add honeypot-specific aggregations
            if hp_name == "cowrie":
                # Support both old (json.*) and new (cowrie.*) field structures
                aggs["sessions_old"] = {"cardinality": {"field": "json.session"}}
                aggs["sessions_new"] = {"cardinality": {"field": "cowrie.session"}}
                aggs["login_success"] = {"filter": {"bool": {"should": [
                    {"term": {"json.eventid": "cowrie.login.success"}},
                    {"term": {"cowrie.eventid": "cowrie.login.success"}}
                ], "minimum_should_match": 1}}}
                aggs["login_failed"] = {"filter": {"bool": {"should": [
                    {"term": {"json.eventid": "cowrie.login.failed"}},
                    {"term": {"cowrie.eventid": "cowrie.login.failed"}}
                ], "minimum_should_match": 1}}}
            elif hp_name == "heralding":
                aggs["auth_attempts"] = {"sum": {"field": "num_auth_attempts"}}
            elif hp_name == "galah":
                pass  # Web requests counted as total events
            
            result = await es.search(index=index, query=query, size=0, aggs=aggs)
            
            events = result.get("hits", {}).get("total", {}).get("value", 0)
            
            # For Cowrie, combine both field aggregations
            if hp_name == "cowrie":
                unique_ips_old = result.get("aggregations", {}).get("unique_ips_old", {}).get("value", 0)
                unique_ips_new = result.get("aggregations", {}).get("unique_ips_new", {}).get("value", 0)
                unique_ips = max(unique_ips_old, unique_ips_new)
            else:
                unique_ips = result.get("aggregations", {}).get("unique_ips", {}).get("value", 0)
            
            kpis["total_events"] += events
            kpis["unique_ips"] += unique_ips
            
            if hp_name == "cowrie":
                sessions_old = result.get("aggregations", {}).get("sessions_old", {}).get("value", 0)
                sessions_new = result.get("aggregations", {}).get("sessions_new", {}).get("value", 0)
                sessions = max(sessions_old, sessions_new)  # Use whichever has more data
                login_success = result.get("aggregations", {}).get("login_success", {}).get("doc_count", 0)
                login_failed = result.get("aggregations", {}).get("login_failed", {}).get("doc_count", 0)
                kpis["total_sessions"] += sessions
                kpis["successful_logins"] += login_success
                kpis["auth_attempts"] += login_success + login_failed
            elif hp_name == "heralding":
                auth = int(result.get("aggregations", {}).get("auth_attempts", {}).get("value", 0))
                kpis["auth_attempts"] += auth
            elif hp_name == "galah":
                kpis["web_requests"] += events
            
            honeypot_breakdown[hp_name] = {
                "events": events,
                "unique_ips": unique_ips,
            }
        except Exception as e:
            honeypot_breakdown[hp_name] = {"events": 0, "unique_ips": 0, "error": str(e)}
    
    query_time = int((datetime.now() - start_time).total_seconds() * 1000)
    
    return {
        "kpis": kpis,
        "honeypot_breakdown": honeypot_breakdown,
        "time_range": time_range,
        "query_time_ms": query_time,
        "generated_at": datetime.now().isoformat(),
    }


@router.get("/overview/timeline")
async def get_analytics_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    honeypot: Optional[str] = None,
    _: str = Depends(get_current_user)
):
    """Get events over time for timeline chart."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    indices = [INDICES[honeypot]] if honeypot and honeypot in INDICES else list(INDICES.values())
    
    timeline_data = {}
    by_honeypot = {}
    
    for hp_name, index in INDICES.items():
        if honeypot and hp_name != honeypot:
            continue
        
        try:
            result = await es.search(
                index=index,
                query=es._get_time_range_query(time_range),
                size=0,
                aggs={
                    "timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": interval,
                        }
                    }
                }
            )
            
            hp_timeline = []
            for bucket in result.get("aggregations", {}).get("timeline", {}).get("buckets", []):
                ts = bucket["key_as_string"]
                count = bucket["doc_count"]
                timeline_data[ts] = timeline_data.get(ts, 0) + count
                hp_timeline.append({"timestamp": ts, "count": count})
            
            by_honeypot[hp_name] = hp_timeline
        except Exception:
            pass
    
    return {
        "timeline": [{"timestamp": ts, "count": count} for ts, count in sorted(timeline_data.items())],
        "by_honeypot": by_honeypot,
        "interval": interval,
        "time_range": time_range,
    }


@router.get("/overview/top-attackers")
async def get_analytics_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    honeypot: Optional[str] = None,
    _: str = Depends(get_current_user)
):
    """Get top attacking IPs with metadata."""
    es = get_es_service()
    
    ip_data = {}
    
    for hp_name, index in INDICES.items():
        if honeypot and hp_name != honeypot:
            continue
        
        # For Cowrie, we need to query both old (json.src_ip) and new (cowrie.src_ip) fields
        if hp_name == "cowrie":
            ip_fields = ["json.src_ip", "cowrie.src_ip"]
        else:
            ip_fields = [IP_FIELDS.get(hp_name, "source.ip")]
        
        for ip_field in ip_fields:
            try:
                result = await es.search(
                    index=index,
                    query=es._get_time_range_query(time_range),
                    size=0,
                    aggs={
                        "top_ips": {
                            "terms": {"field": ip_field, "size": 100},
                            "aggs": {
                                "geo": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": ["source.geo.country_name", "source.geo.city_name", "geoip.country_name"]
                                    }
                                },
                                "first_seen": {"min": {"field": "@timestamp"}},
                                "last_seen": {"max": {"field": "@timestamp"}},
                            }
                        }
                    }
                )
                
                for bucket in result.get("aggregations", {}).get("top_ips", {}).get("buckets", []):
                    ip = bucket["key"]
                    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "127.")):
                        continue
                    
                    if ip not in ip_data:
                        hits = bucket.get("geo", {}).get("hits", {}).get("hits", [])
                        geo = {}
                        if hits:
                            source = hits[0].get("_source", {})
                            geo = source.get("source", {}).get("geo", source.get("geoip", {}))
                        
                        ip_data[ip] = {
                            "ip": ip,
                            "events": 0,
                            "honeypots": [],
                            "country": geo.get("country_name"),
                            "city": geo.get("city_name"),
                            "first_seen": bucket.get("first_seen", {}).get("value_as_string"),
                            "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
                        }
                    
                    ip_data[ip]["events"] += bucket["doc_count"]
                    if hp_name not in ip_data[ip]["honeypots"]:
                        ip_data[ip]["honeypots"].append(hp_name)
            except Exception:
                pass
    
    # Sort by events and return top N
    attackers = sorted(ip_data.values(), key=lambda x: -x["events"])[:limit]
    
    return {
        "attackers": attackers,
        "total": len(ip_data),
        "time_range": time_range,
    }


@router.get("/overview/protocols")
async def get_analytics_protocols(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get protocol/service distribution."""
    es = get_es_service()
    
    protocols = {}
    
    # Map honeypots to protocols
    protocol_mapping = {
        "cowrie": "SSH/Telnet",
        "galah": "HTTP",
        "rdpy": "RDP",
    }
    
    for hp_name, proto in protocol_mapping.items():
        try:
            events = await es.get_total_events(INDICES[hp_name], time_range)
            protocols[proto] = protocols.get(proto, 0) + events
        except Exception:
            pass
    
    # Heralding has multiple protocols
    try:
        result = await es.search(
            index=INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"by_protocol": {"terms": {"field": "network.protocol.keyword", "size": 20}}}
        )
        for bucket in result.get("aggregations", {}).get("by_protocol", {}).get("buckets", []):
            proto = bucket["key"].upper()
            protocols[proto] = protocols.get(proto, 0) + bucket["doc_count"]
    except Exception:
        pass
    
    # Dionaea by port
    try:
        result = await es.search(
            index=INDICES["dionaea"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"by_port": {"terms": {"field": "destination.port", "size": 10}}}
        )
        port_names = {21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL"}
        for bucket in result.get("aggregations", {}).get("by_port", {}).get("buckets", []):
            port = bucket["key"]
            proto = port_names.get(port, f"Port {port}")
            protocols[proto] = protocols.get(proto, 0) + bucket["doc_count"]
    except Exception:
        pass
    
    return {
        "protocols": sorted([{"protocol": k, "count": v} for k, v in protocols.items()], key=lambda x: -x["count"]),
        "time_range": time_range,
    }


@router.get("/overview/countries")
async def get_analytics_countries(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get geographic distribution of attacks."""
    es = get_es_service()
    
    country_data = {}
    
    for hp_name, index in INDICES.items():
        geo_field = GEO_FIELDS.get(hp_name, "source.geo.country_name")
        
        try:
            result = await es.search(
                index=index,
                query=es._get_time_range_query(time_range),
                size=0,
                aggs={"by_country": {"terms": {"field": geo_field, "size": 50}}}
            )
            
            for bucket in result.get("aggregations", {}).get("by_country", {}).get("buckets", []):
                country = bucket["key"]
                count = bucket["doc_count"]
                
                if country not in country_data:
                    country_data[country] = {"country": country, "total": 0, "by_honeypot": {}}
                
                country_data[country]["total"] += count
                country_data[country]["by_honeypot"][hp_name] = country_data[country]["by_honeypot"].get(hp_name, 0) + count
        except Exception:
            pass
    
    countries = sorted(country_data.values(), key=lambda x: -x["total"])[:limit]
    
    return {
        "countries": countries,
        "total_countries": len(country_data),
        "time_range": time_range,
    }


# ==================== HEALTH ENDPOINTS ====================

@router.get("/health")
async def get_analytics_health(
    _: str = Depends(get_current_user)
):
    """Get honeypot health status."""
    es = get_es_service()
    
    honeypots = []
    
    for hp_name, index in INDICES.items():
        try:
            # Get last event
            result = await es.search(
                index=index,
                query={"match_all": {}},
                size=1,
                sort=[{"@timestamp": "desc"}]
            )
            
            hits = result.get("hits", {}).get("hits", [])
            last_event = hits[0]["_source"].get("@timestamp") if hits else None
            
            # Get counts
            events_1h = await es.get_total_events(index, "1h")
            events_24h = await es.get_total_events(index, "24h")
            
            # Calculate status
            status = "offline"
            minutes_ago = None
            
            if last_event:
                try:
                    last_dt = datetime.fromisoformat(last_event.replace("Z", "+00:00"))
                    now = datetime.now(last_dt.tzinfo)
                    minutes_ago = (now - last_dt).total_seconds() / 60
                    
                    if minutes_ago < 15:
                        status = "healthy"
                    elif minutes_ago < 60:
                        status = "warning"
                    else:
                        status = "stale"
                except Exception:
                    status = "unknown"
            
            honeypots.append({
                "id": hp_name,
                "name": hp_name.capitalize(),
                "index": index,
                "status": status,
                "last_event": last_event,
                "minutes_since_last": round(minutes_ago, 1) if minutes_ago else None,
                "events_1h": events_1h,
                "events_24h": events_24h,
            })
        except Exception as e:
            honeypots.append({
                "id": hp_name,
                "name": hp_name.capitalize(),
                "index": index,
                "status": "error",
                "error": str(e),
            })
    
    healthy = sum(1 for h in honeypots if h.get("status") == "healthy")
    
    return {
        "honeypots": honeypots,
        "summary": {
            "healthy": healthy,
            "total": len(honeypots),
            "overall_status": "healthy" if healthy == len(honeypots) else "degraded" if healthy > 0 else "critical",
        },
    }


@router.get("/health/coverage-matrix")
async def get_coverage_matrix(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get honeypot x protocol coverage matrix."""
    es = get_es_service()
    
    # Define which protocols each honeypot covers
    coverage = {
        "cowrie": {"SSH": 0, "Telnet": 0},
        "dionaea": {"SMB": 0, "FTP": 0, "HTTP": 0, "MySQL": 0, "MSSQL": 0},
        "galah": {"HTTP": 0, "HTTPS": 0},
        "rdpy": {"RDP": 0},
        "heralding": {"SSH": 0, "Telnet": 0, "HTTP": 0, "FTP": 0, "VNC": 0, "MySQL": 0, "PostgreSQL": 0},
    }
    
    # Get Heralding protocol breakdown
    try:
        result = await es.search(
            index=INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"by_protocol": {"terms": {"field": "network.protocol.keyword", "size": 20}}}
        )
        for bucket in result.get("aggregations", {}).get("by_protocol", {}).get("buckets", []):
            proto = bucket["key"].upper()
            if proto in coverage["heralding"]:
                coverage["heralding"][proto] = bucket["doc_count"]
    except Exception:
        pass
    
    # Get counts for other honeypots
    for hp_name in ["cowrie", "galah", "rdpy"]:
        try:
            events = await es.get_total_events(INDICES[hp_name], time_range)
            for proto in coverage[hp_name]:
                coverage[hp_name][proto] = events
        except Exception:
            pass
    
    # Dionaea by port
    try:
        result = await es.search(
            index=INDICES["dionaea"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"by_port": {"terms": {"field": "destination.port", "size": 20}}}
        )
        port_protos = {445: "SMB", 21: "FTP", 80: "HTTP", 3306: "MySQL", 1433: "MSSQL"}
        for bucket in result.get("aggregations", {}).get("by_port", {}).get("buckets", []):
            port = bucket["key"]
            proto = port_protos.get(port)
            if proto and proto in coverage["dionaea"]:
                coverage["dionaea"][proto] = bucket["doc_count"]
    except Exception:
        pass
    
    return {
        "matrix": coverage,
        "time_range": time_range,
    }


# ==================== EVENTS/TIMELINE SEARCH ====================

@router.get("/events/search")
async def search_events(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    q: Optional[str] = None,
    honeypot: Optional[str] = None,
    src_ip: Optional[str] = None,
    session_id: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Search events with filtering."""
    es = get_es_service()
    
    indices = [INDICES[honeypot]] if honeypot and honeypot in INDICES else ",".join(INDICES.values())
    
    query = build_filter_query(time_range, honeypot=honeypot, src_ip=src_ip, session_id=session_id)
    
    # Add free text search
    if q:
        query["bool"]["must"].append({
            "query_string": {
                "query": f"*{q}*",
                "fields": ["json.input", "json.username", "json.password", "url.path", "user_agent.original"],
            }
        })
    
    result = await es.search(
        index=indices,
        query=query,
        size=size,
        sort=[{"@timestamp": "desc"}],
        from_=(page - 1) * size,
    )
    
    events = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        events.append({
            "id": hit["_id"],
            "index": hit["_index"],
            "timestamp": source.get("@timestamp"),
            "honeypot": next((k for k, v in INDICES.items() if v.replace("*", "") in hit["_index"]), "unknown"),
            "src_ip": source.get("source", {}).get("ip") or source.get("json", {}).get("src_ip"),
            "event_type": source.get("json", {}).get("eventid") or source.get("msg"),
            "summary": _get_event_summary(source),
        })
    
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    
    return {
        "events": events,
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "time_range": time_range,
    }


def _get_event_summary(source: Dict) -> str:
    """Generate a human-readable summary of an event."""
    json_data = source.get("json", {})
    
    if "eventid" in json_data:
        eventid = json_data["eventid"]
        if "login" in eventid:
            return f"Login attempt: {json_data.get('username', '?')} / {json_data.get('password', '?')}"
        elif "command" in eventid:
            return f"Command: {json_data.get('input', '?')[:100]}"
        elif "session" in eventid:
            return f"Session: {eventid}"
        return eventid
    
    if "url" in source:
        return f"{source.get('http', {}).get('request', {}).get('method', 'GET')} {source['url'].get('path', '/')}"
    
    if "msg" in source:
        return source["msg"][:100]
    
    return "Event"


@router.get("/events/{event_id}")
async def get_event_detail(
    event_id: str,
    index: str = Query(...),
    _: str = Depends(get_current_user)
):
    """Get full event details."""
    es = get_es_service()
    
    try:
        # Use search with ids query for data stream compatibility
        result = await es.search(
            index=index,
            query={"ids": {"values": [event_id]}},
            size=1
        )
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            hit = hits[0]
            return {
                "id": hit["_id"],
                "index": hit["_index"],
                "source": hit["_source"],
            }
        return {"error": "Event not found"}
    except Exception as e:
        return {"error": str(e)}


# ==================== CREDENTIALS ENDPOINTS ====================

@router.get("/credentials/top")
async def get_top_credentials(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top usernames and passwords."""
    es = get_es_service()
    
    usernames = {}
    passwords = {}
    
    # Cowrie credentials (support both old json.* and new cowrie.* fields)
    field_configs = [
        {"eventid": "json.eventid", "username": "json.username", "password": "json.password"},
        {"eventid": "cowrie.eventid", "username": "cowrie.username", "password": "cowrie.password"},
    ]
    
    for fields in field_configs:
        try:
            result = await es.search(
                index=INDICES["cowrie"],
                query={
                    "bool": {
                        "must": [
                            es._get_time_range_query(time_range),
                            {"terms": {fields["eventid"]: ["cowrie.login.success", "cowrie.login.failed"]}}
                        ]
                    }
                },
                size=0,
                aggs={
                    "usernames": {"terms": {"field": fields["username"], "size": limit}},
                    "passwords": {"terms": {"field": fields["password"], "size": limit}},
                }
            )
            
            for bucket in result.get("aggregations", {}).get("usernames", {}).get("buckets", []):
                usernames[bucket["key"]] = usernames.get(bucket["key"], 0) + bucket["doc_count"]
            for bucket in result.get("aggregations", {}).get("passwords", {}).get("buckets", []):
                passwords[bucket["key"]] = passwords.get(bucket["key"], 0) + bucket["doc_count"]
        except Exception:
            pass
    
    # Heralding credentials
    try:
        result = await es.search(
            index=INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "usernames": {"terms": {"field": "user.name.keyword", "size": limit}},
                "passwords": {"terms": {"field": "user.password.keyword", "size": limit}},
            }
        )
        
        for bucket in result.get("aggregations", {}).get("usernames", {}).get("buckets", []):
            usernames[bucket["key"]] = usernames.get(bucket["key"], 0) + bucket["doc_count"]
        for bucket in result.get("aggregations", {}).get("passwords", {}).get("buckets", []):
            passwords[bucket["key"]] = passwords.get(bucket["key"], 0) + bucket["doc_count"]
    except Exception:
        pass
    
    return {
        "usernames": sorted([{"username": k, "count": v} for k, v in usernames.items()], key=lambda x: -x["count"])[:limit],
        "passwords": sorted([{"password": k, "count": v} for k, v in passwords.items()], key=lambda x: -x["count"])[:limit],
        "time_range": time_range,
    }


@router.get("/credentials/pairs")
async def get_credential_pairs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=30, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get username/password pair combinations."""
    es = get_es_service()
    
    pairs = {}
    
    # Cowrie (support both old json.* and new cowrie.* fields)
    cowrie_field_configs = [
        {"eventid": "json.eventid", "username": "json.username", "password": "json.password"},
        {"eventid": "cowrie.eventid", "username": "cowrie.username", "password": "cowrie.password"},
    ]
    
    for fields in cowrie_field_configs:
        try:
            result = await es.search(
                index=INDICES["cowrie"],
                query={
                    "bool": {
                        "must": [
                            es._get_time_range_query(time_range),
                            {"terms": {fields["eventid"]: ["cowrie.login.success", "cowrie.login.failed"]}}
                        ]
                    }
                },
                size=0,
                aggs={
                    "pairs": {
                        "composite": {
                            "size": 1000,
                            "sources": [
                                {"username": {"terms": {"field": fields["username"]}}},
                                {"password": {"terms": {"field": fields["password"]}}}
                            ]
                        }
                    }
                }
            )
            
            for bucket in result.get("aggregations", {}).get("pairs", {}).get("buckets", []):
                key = (bucket["key"]["username"], bucket["key"]["password"])
                pairs[key] = pairs.get(key, 0) + bucket["doc_count"]
        except Exception:
            pass
    
    sorted_pairs = sorted(pairs.items(), key=lambda x: -x[1])[:limit]
    
    return {
        "pairs": [
            {"username": k[0], "password": k[1], "count": v}
            for k, v in sorted_pairs
        ],
        "total_unique_pairs": len(pairs),
        "time_range": time_range,
    }


@router.get("/credentials/reuse")
async def get_credential_reuse(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Analyze credential reuse patterns."""
    es = get_es_service()
    
    # Passwords used by multiple IPs (support both old and new Cowrie fields)
    password_ips = {}
    username_ips = {}
    
    reuse_field_configs = [
        {"eventid": "json.eventid", "password": "json.password", "username": "json.username", "src_ip": "json.src_ip"},
        {"eventid": "cowrie.eventid", "password": "cowrie.password", "username": "cowrie.username", "src_ip": "cowrie.src_ip"},
    ]
    
    for fields in reuse_field_configs:
        try:
            result = await es.search(
                index=INDICES["cowrie"],
                query={
                    "bool": {
                        "must": [
                            es._get_time_range_query(time_range),
                            {"terms": {fields["eventid"]: ["cowrie.login.success", "cowrie.login.failed"]}}
                        ]
                    }
                },
                size=0,
                aggs={
                    "passwords": {
                        "terms": {"field": fields["password"], "size": 100},
                        "aggs": {"unique_ips": {"cardinality": {"field": fields["src_ip"]}}}
                    },
                    "usernames": {
                        "terms": {"field": fields["username"], "size": 100},
                        "aggs": {"unique_ips": {"cardinality": {"field": fields["src_ip"]}}}
                    }
                }
            )
            
            for bucket in result.get("aggregations", {}).get("passwords", {}).get("buckets", []):
                ip_count = bucket.get("unique_ips", {}).get("value", 0)
                if ip_count >= 2:
                    password_ips[bucket["key"]] = max(password_ips.get(bucket["key"], 0), ip_count)
            
            for bucket in result.get("aggregations", {}).get("usernames", {}).get("buckets", []):
                ip_count = bucket.get("unique_ips", {}).get("value", 0)
                if ip_count >= 2:
                    username_ips[bucket["key"]] = max(username_ips.get(bucket["key"], 0), ip_count)
        except Exception:
            pass
    
    return {
        "reused_passwords": sorted(
            [{"password": k, "ip_count": v} for k, v in password_ips.items()],
            key=lambda x: -x["ip_count"]
        )[:20],
        "reused_usernames": sorted(
            [{"username": k, "ip_count": v} for k, v in username_ips.items()],
            key=lambda x: -x["ip_count"]
        )[:20],
        "time_range": time_range,
    }


# ==================== COWRIE SESSIONS ====================

@router.get("/cowrie/sessions")
async def get_cowrie_sessions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    variant: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    has_commands: Optional[bool] = Query(default=None, description="Filter by command presence"),
    _: str = Depends(get_current_user)
):
    """Get Cowrie session list with optional filtering."""
    es = get_es_service()
    
    must_clauses = [es._get_time_range_query(time_range)]
    if variant:
        must_clauses.append({"term": {"cowrie_variant": variant}})
    
    # If filtering for sessions WITH commands, first find those session IDs
    target_session_ids = None
    if has_commands is True:
        cmd_query = {"bool": {"must": must_clauses + [
            {"bool": {"should": [
                {"term": {"cowrie.eventid": "cowrie.command.input"}},
                {"term": {"json.eventid": "cowrie.command.input"}}
            ]}}
        ]}}
        
        cmd_result = await es.search(
            index=INDICES["cowrie"],
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
            return {"sessions": [], "total": 0, "time_range": time_range}
        
        # Query those specific sessions directly
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
                index=INDICES["cowrie"],
                query=session_query,
                size=0,
                aggs={
                    "variant": {"terms": {"field": "cowrie_variant", "size": 1}},
                    "src_ip": {"top_hits": {"size": 1, "_source": ["cowrie.src_ip", "json.src_ip"]}},
                    "commands": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.command.input"}},
                        {"term": {"json.eventid": "cowrie.command.input"}}
                    ]}}},
                    "login_success": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.login.success"}},
                        {"term": {"json.eventid": "cowrie.login.success"}}
                    ]}}},
                    "first_event": {"min": {"field": "@timestamp"}},
                    "last_event": {"max": {"field": "@timestamp"}},
                }
            )
            
            if result.get("hits", {}).get("total", {}).get("value", 0) == 0:
                continue
            
            aggs = result.get("aggregations", {})
            variant_buckets = aggs.get("variant", {}).get("buckets", [])
            hit_source = aggs.get("src_ip", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
            
            first = aggs.get("first_event", {}).get("value_as_string")
            last = aggs.get("last_event", {}).get("value_as_string")
            duration = 0
            if first and last:
                try:
                    first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    duration = (last_dt - first_dt).total_seconds()
                except Exception:
                    pass
            
            sessions.append({
                "session_id": session_id,
                "variant": variant_buckets[0]["key"] if variant_buckets else None,
                "src_ip": hit_source.get("cowrie", {}).get("src_ip") or hit_source.get("json", {}).get("src_ip"),
                "events": result.get("hits", {}).get("total", {}).get("value", 0),
                "commands": aggs.get("commands", {}).get("doc_count", 0),
                "login_success": aggs.get("login_success", {}).get("doc_count", 0) > 0,
                "duration": round(duration, 2),
                "first_event": first,
                "last_event": last,
            })
        
        sessions.sort(key=lambda x: -x["duration"])
        return {"sessions": sessions, "total": len(sessions), "time_range": time_range}
    
    # Standard aggregation for all sessions or empty-only filter
    query = {"bool": {"must": must_clauses}}
    fetch_limit = limit * 3 if has_commands is False else limit
    
    all_sessions = []
    
    for session_field, ip_field, eventid_field in [
        ("json.session", "json.src_ip", "json.eventid"),
        ("cowrie.session", "cowrie.src_ip", "cowrie.eventid"),
    ]:
        result = await es.search(
            index=INDICES["cowrie"],
            query=query,
            size=0,
            aggs={
                "sessions": {
                    "terms": {"field": session_field, "size": fetch_limit},
                    "aggs": {
                        "variant": {"terms": {"field": "cowrie_variant", "size": 1}},
                        "src_ip": {"terms": {"field": ip_field, "size": 1}},
                        "commands": {"filter": {"term": {eventid_field: "cowrie.command.input"}}},
                        "login_success": {"filter": {"term": {eventid_field: "cowrie.login.success"}}},
                        "first_event": {"min": {"field": "@timestamp"}},
                        "last_event": {"max": {"field": "@timestamp"}},
                    }
                }
            }
        )
        
        for bucket in result.get("aggregations", {}).get("sessions", {}).get("buckets", []):
            all_sessions.append(bucket)
    
    # Deduplicate sessions by session_id (in case same session appears in both field queries)
    seen_sessions = set()
    sessions = []
    
    for bucket in all_sessions:
        session_id = bucket["key"]
        if session_id in seen_sessions:
            continue
        seen_sessions.add(session_id)
        
        variant_buckets = bucket.get("variant", {}).get("buckets", [])
        ip_buckets = bucket.get("src_ip", {}).get("buckets", [])
        
        first = bucket.get("first_event", {}).get("value_as_string")
        last = bucket.get("last_event", {}).get("value_as_string")
        duration = 0
        if first and last:
            try:
                first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                duration = (last_dt - first_dt).total_seconds()
            except Exception:
                pass
        
        commands_count = bucket.get("commands", {}).get("doc_count", 0)
        
        # Apply has_commands filter
        if has_commands is not None:
            if has_commands and commands_count == 0:
                continue
            if not has_commands and commands_count > 0:
                continue
        
        sessions.append({
            "session_id": session_id,
            "variant": variant_buckets[0]["key"] if variant_buckets else None,
            "src_ip": ip_buckets[0]["key"] if ip_buckets else None,
            "events": bucket["doc_count"],
            "commands": commands_count,
            "login_success": bucket.get("login_success", {}).get("doc_count", 0) > 0,
            "duration": round(duration, 2),
            "first_event": first,
            "last_event": last,
        })
    
    # Sort by duration desc and limit
    sessions.sort(key=lambda x: -x["duration"])
    sessions = sessions[:limit]
    
    return {
        "sessions": sessions,
        "total": len(sessions),
        "time_range": time_range,
    }


@router.get("/cowrie/distributions")
async def get_cowrie_distributions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get distribution charts for Cowrie sessions by variant."""
    es = get_es_service()
    
    result = await es.search(
        index=INDICES["cowrie"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_variant": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    # Support both old (json.*) and new (cowrie.*) field structures
                    "sessions_old": {"cardinality": {"field": "json.session"}},
                    "sessions_new": {"cardinality": {"field": "cowrie.session"}},
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}},
                    "commands": {"filter": {"bool": {"should": [
                        {"term": {"json.eventid": "cowrie.command.input"}},
                        {"term": {"cowrie.eventid": "cowrie.command.input"}}
                    ], "minimum_should_match": 1}}},
                    "login_success": {"filter": {"bool": {"should": [
                        {"term": {"json.eventid": "cowrie.login.success"}},
                        {"term": {"cowrie.eventid": "cowrie.login.success"}}
                    ], "minimum_should_match": 1}}},
                    "login_failed": {"filter": {"bool": {"should": [
                        {"term": {"json.eventid": "cowrie.login.failed"}},
                        {"term": {"cowrie.eventid": "cowrie.login.failed"}}
                    ], "minimum_should_match": 1}}},
                }
            }
        }
    )
    
    variants = []
    for bucket in result.get("aggregations", {}).get("by_variant", {}).get("buckets", []):
        sessions_old = bucket.get("sessions_old", {}).get("value", 0)
        sessions_new = bucket.get("sessions_new", {}).get("value", 0)
        sessions = max(sessions_old, sessions_new)
        unique_ips_old = bucket.get("unique_ips_old", {}).get("value", 0)
        unique_ips_new = bucket.get("unique_ips_new", {}).get("value", 0)
        unique_ips = max(unique_ips_old, unique_ips_new)
        commands = bucket.get("commands", {}).get("doc_count", 0)
        
        variants.append({
            "variant": bucket["key"],
            "events": bucket["doc_count"],
            "sessions": sessions,
            "unique_ips": unique_ips,
            "commands": commands,
            "login_success": bucket.get("login_success", {}).get("doc_count", 0),
            "login_failed": bucket.get("login_failed", {}).get("doc_count", 0),
            "commands_per_session": round(commands / sessions, 2) if sessions > 0 else 0,
        })
    
    return {
        "variants": variants,
        "time_range": time_range,
    }


@router.get("/cowrie/variant-study")
async def get_cowrie_variant_study(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Comprehensive study comparing Cowrie variants (plain, openai, ollama).
    Only includes sessions with at least 1 command executed.
    """
    es = get_es_service()
    
    # First, find all sessions with commands for each variant
    variants_data = {}
    
    for variant in ["plain", "openai", "ollama"]:
        # Find sessions with commands for this variant
        cmd_query = {"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"cowrie_variant": variant}},
            {"bool": {"should": [
                {"term": {"cowrie.eventid": "cowrie.command.input"}},
                {"term": {"json.eventid": "cowrie.command.input"}}
            ]}}
        ]}}
        
        # Get session IDs that have commands
        cmd_result = await es.search(
            index=INDICES["cowrie"],
            query=cmd_query,
            size=0,
            aggs={
                "sessions": {
                    "terms": {"field": "cowrie.session", "size": 5000},
                    "aggs": {
                        "cmd_count": {"value_count": {"field": "@timestamp"}}
                    }
                },
                "sessions_old": {
                    "terms": {"field": "json.session", "size": 5000},
                    "aggs": {
                        "cmd_count": {"value_count": {"field": "@timestamp"}}
                    }
                }
            }
        )
        
        session_cmd_counts = {}
        for bucket in cmd_result.get("aggregations", {}).get("sessions", {}).get("buckets", []):
            session_cmd_counts[bucket["key"]] = bucket["doc_count"]
        for bucket in cmd_result.get("aggregations", {}).get("sessions_old", {}).get("buckets", []):
            if bucket["key"] not in session_cmd_counts:
                session_cmd_counts[bucket["key"]] = bucket["doc_count"]
        
        if not session_cmd_counts:
            variants_data[variant] = {
                "total_sessions_with_commands": 0,
                "total_commands": 0,
                "avg_commands_per_session": 0,
                "avg_session_duration": 0,
                "max_commands_in_session": 0,
                "unique_attackers": 0,
                "successful_logins": 0,
                "failed_logins": 0,
                "login_success_rate": 0,
                "file_downloads": 0,
                "sessions_with_downloads": 0,
                "sessions": []
            }
            continue
        
        # Get detailed stats for these sessions
        session_ids = list(session_cmd_counts.keys())
        total_commands = sum(session_cmd_counts.values())
        max_commands = max(session_cmd_counts.values()) if session_cmd_counts else 0
        
        # Get session durations and other details
        session_details = []
        unique_ips = set()
        total_duration = 0
        successful_logins = 0
        failed_logins = 0
        file_downloads = 0
        sessions_with_downloads = 0
        
        # Process sessions in batches
        for session_id in session_ids[:500]:  # Limit to 500 sessions for performance
            session_query = {"bool": {"must": [
                es._get_time_range_query(time_range),
                {"term": {"cowrie_variant": variant}},
                {"bool": {"should": [
                    {"term": {"cowrie.session": session_id}},
                    {"term": {"json.session": session_id}}
                ]}}
            ]}}
            
            result = await es.search(
                index=INDICES["cowrie"],
                query=session_query,
                size=0,
                aggs={
                    "src_ip": {"top_hits": {"size": 1, "_source": ["cowrie.src_ip", "json.src_ip", "cowrie.geo.country_name", "source.geo.country_name"]}},
                    "first_event": {"min": {"field": "@timestamp"}},
                    "last_event": {"max": {"field": "@timestamp"}},
                    "login_success": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.login.success"}},
                        {"term": {"json.eventid": "cowrie.login.success"}}
                    ]}}},
                    "login_failed": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.login.failed"}},
                        {"term": {"json.eventid": "cowrie.login.failed"}}
                    ]}}},
                    "file_download": {"filter": {"bool": {"should": [
                        {"term": {"cowrie.eventid": "cowrie.session.file_download"}},
                        {"term": {"json.eventid": "cowrie.session.file_download"}}
                    ]}}}
                }
            )
            
            aggs = result.get("aggregations", {})
            hit_source = aggs.get("src_ip", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
            
            src_ip = hit_source.get("cowrie", {}).get("src_ip") or hit_source.get("json", {}).get("src_ip")
            country = hit_source.get("cowrie", {}).get("geo", {}).get("country_name") or hit_source.get("source", {}).get("geo", {}).get("country_name")
            
            if src_ip:
                unique_ips.add(src_ip)
            
            first = aggs.get("first_event", {}).get("value_as_string")
            last = aggs.get("last_event", {}).get("value_as_string")
            duration = 0
            if first and last:
                try:
                    first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    duration = (last_dt - first_dt).total_seconds()
                    total_duration += duration
                except:
                    pass
            
            login_success_count = aggs.get("login_success", {}).get("doc_count", 0)
            login_failed_count = aggs.get("login_failed", {}).get("doc_count", 0)
            download_count = aggs.get("file_download", {}).get("doc_count", 0)
            
            successful_logins += login_success_count
            failed_logins += login_failed_count
            file_downloads += download_count
            if download_count > 0:
                sessions_with_downloads += 1
            
            session_details.append({
                "session_id": session_id,
                "commands": session_cmd_counts.get(session_id, 0),
                "duration": round(duration, 2),
                "src_ip": src_ip,
                "country": country,
                "login_success": login_success_count > 0,
                "has_download": download_count > 0
            })
        
        # Sort by commands desc
        session_details.sort(key=lambda x: -x["commands"])
        
        total_sessions = len(session_ids)
        avg_duration = total_duration / len(session_details) if session_details else 0
        total_logins = successful_logins + failed_logins
        
        variants_data[variant] = {
            "total_sessions_with_commands": total_sessions,
            "total_commands": total_commands,
            "avg_commands_per_session": round(total_commands / total_sessions, 2) if total_sessions > 0 else 0,
            "avg_session_duration": round(avg_duration, 2),
            "max_commands_in_session": max_commands,
            "unique_attackers": len(unique_ips),
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "login_success_rate": round((successful_logins / total_logins) * 100, 1) if total_logins > 0 else 0,
            "file_downloads": file_downloads,
            "sessions_with_downloads": sessions_with_downloads,
            "top_sessions": session_details[:10]  # Top 10 sessions by command count
        }
    
    # Calculate comparison metrics
    comparison = {
        "engagement_winner": max(variants_data.keys(), key=lambda v: variants_data[v]["avg_commands_per_session"]) if any(variants_data[v]["total_sessions_with_commands"] > 0 for v in variants_data) else None,
        "duration_winner": max(variants_data.keys(), key=lambda v: variants_data[v]["avg_session_duration"]) if any(variants_data[v]["total_sessions_with_commands"] > 0 for v in variants_data) else None,
        "download_winner": max(variants_data.keys(), key=lambda v: variants_data[v]["sessions_with_downloads"]) if any(variants_data[v]["sessions_with_downloads"] > 0 for v in variants_data) else None,
    }
    
    return {
        "variants": variants_data,
        "comparison": comparison,
        "time_range": time_range,
        "generated_at": datetime.now().isoformat(),
    }


# ==================== COMMANDS ====================

@router.get("/cowrie/commands/top")
async def get_top_commands(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    variant: Optional[str] = None,
    src_ip: Optional[str] = None,
    country: Optional[str] = None,
    limit: int = Query(default=30, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top commands executed with optional filtering by variant, source IP, or country."""
    es = get_es_service()
    
    # Support both old (json.eventid) and new (cowrie.eventid) field structures
    query = {
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
                }
            ]
        }
    }
    
    if variant:
        query["bool"]["must"].append({"term": {"cowrie_variant": variant}})
    if src_ip:
        # Support both old and new field structures
        query["bool"]["must"].append({
            "bool": {
                "should": [
                    {"term": {"json.src_ip": src_ip}},
                    {"term": {"cowrie.src_ip": src_ip}}
                ],
                "minimum_should_match": 1
            }
        })
    if country:
        query["bool"]["must"].append({
            "bool": {
                "should": [
                    {"match": {"source.geo.country_name": country}},
                    {"match": {"cowrie.geo.country_name": country}}
                ],
                "minimum_should_match": 1
            }
        })
    
    result = await es.search(
        index=INDICES["cowrie"],
        query=query,
        size=0,
        aggs={
            "commands": {
                "terms": {"field": "json.input", "size": limit},
                "aggs": {
                    "by_variant": {"terms": {"field": "cowrie_variant", "size": 5}},
                    # Support both field structures for unique IPs
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}},
                }
            }
        }
    )
    
    commands = []
    for bucket in result.get("aggregations", {}).get("commands", {}).get("buckets", []):
        by_variant = {b["key"]: b["doc_count"] for b in bucket.get("by_variant", {}).get("buckets", [])}
        # Combine unique IPs from both old and new field structures
        unique_ips_old = bucket.get("unique_ips_old", {}).get("value", 0)
        unique_ips_new = bucket.get("unique_ips_new", {}).get("value", 0)
        commands.append({
            "command": bucket["key"],
            "count": bucket["doc_count"],
            "unique_ips": max(unique_ips_old, unique_ips_new),  # Use max since they're the same data
            "by_variant": by_variant,
        })
    
    return {
        "commands": commands,
        "time_range": time_range,
    }


@router.get("/cowrie/sequences")
async def get_command_sequences(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    variant: Optional[str] = None,
    src_ip: Optional[str] = None,
    _: str = Depends(get_current_user)
):
    """Get command sequence patterns (bigrams) with optional filtering."""
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
    if src_ip:
        must_clauses.append({
            "bool": {
                "should": [
                    {"term": {"json.src_ip": src_ip}},
                    {"term": {"cowrie.src_ip": src_ip}}
                ],
                "minimum_should_match": 1
            }
        })
    
    # Get commands grouped by session - try both old and new session fields
    result = await es.search(
        index=INDICES["cowrie"],
        query={"bool": {"must": must_clauses}},
        size=0,
        aggs={
            "sessions_old": {
                "terms": {"field": "json.session", "size": 500},
                "aggs": {
                    "commands": {
                        "top_hits": {
                            "size": 20,
                            "sort": [{"@timestamp": "asc"}],
                            "_source": ["json.input"]
                        }
                    }
                }
            },
            "sessions_new": {
                "terms": {"field": "cowrie.session", "size": 500},
                "aggs": {
                    "commands": {
                        "top_hits": {
                            "size": 20,
                            "sort": [{"@timestamp": "asc"}],
                            "_source": ["json.input"]
                        }
                    }
                }
            }
        }
    )
    
    bigrams = {}
    trigrams = {}
    
    # Process both old and new format sessions
    all_session_buckets = (
        result.get("aggregations", {}).get("sessions_old", {}).get("buckets", []) +
        result.get("aggregations", {}).get("sessions_new", {}).get("buckets", [])
    )
    
    for session_bucket in all_session_buckets:
        commands = [
            hit["_source"]["json"]["input"]
            for hit in session_bucket.get("commands", {}).get("hits", {}).get("hits", [])
            if hit.get("_source", {}).get("json", {}).get("input")
        ]
        
        # Generate bigrams
        for i in range(len(commands) - 1):
            bigram = f"{commands[i]} → {commands[i+1]}"
            bigrams[bigram] = bigrams.get(bigram, 0) + 1
        
        # Generate trigrams
        for i in range(len(commands) - 2):
            trigram = f"{commands[i]} → {commands[i+1]} → {commands[i+2]}"
            trigrams[trigram] = trigrams.get(trigram, 0) + 1
    
    return {
        "bigrams": sorted([{"sequence": k, "count": v} for k, v in bigrams.items()], key=lambda x: -x["count"])[:20],
        "trigrams": sorted([{"sequence": k, "count": v} for k, v in trigrams.items()], key=lambda x: -x["count"])[:20],
        "time_range": time_range,
    }


@router.get("/cowrie/session/{session_id}/timeline")
async def get_session_timeline(
    session_id: str,
    _: str = Depends(get_current_user)
):
    """Get full timeline for a specific session."""
    es = get_es_service()
    
    result = await es.search(
        index=INDICES["cowrie"],
        query={"term": {"json.session": session_id}},
        size=1000,
        sort=[{"@timestamp": "asc"}]
    )
    
    events = []
    session_info = {}
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        json_data = source.get("json", {})
        
        # Extract session info from first connect event
        if json_data.get("eventid") == "cowrie.session.connect" and not session_info:
            session_info = {
                "src_ip": json_data.get("src_ip"),
                "dst_port": json_data.get("dst_port"),
                "protocol": json_data.get("protocol"),
                "sensor": json_data.get("sensor"),
            }
        
        events.append({
            "timestamp": source.get("@timestamp"),
            "event_type": json_data.get("eventid"),
            "details": {
                "input": json_data.get("input"),
                "username": json_data.get("username"),
                "password": json_data.get("password"),
                "message": json_data.get("message"),
            }
        })
    
    return {
        "session_id": session_id,
        "info": session_info,
        "events": events,
        "total_events": len(events),
    }


# ==================== MITRE ====================

@router.get("/mitre/summary")
async def get_mitre_summary(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get MITRE ATT&CK technique summary with severity information."""
    from app.services.mitre import MITRE_TECHNIQUES, TACTICS_ORDER
    
    es = get_es_service()
    technique_counts = {}
    
    # Map Cowrie events to techniques (support both old json.* and new cowrie.* fields)
    event_mapping = {
        "cowrie.login.failed": ["T1110", "T1110.001"],
        "cowrie.login.success": ["T1078"],
        "cowrie.command.input": ["T1059", "T1059.004"],
        "cowrie.session.connect": ["T1021.004"],
        "cowrie.session.file_download": ["T1105"],
        "cowrie.session.file_upload": ["T1041"],
        "cowrie.client.version": ["T1592"],
    }
    
    # Try both old and new field names
    for field_name in ["json.eventid", "cowrie.eventid"]:
        try:
            result = await es.search(
                index=INDICES["cowrie"],
                query=es._get_time_range_query(time_range),
                size=0,
                aggs={"by_event": {"terms": {"field": field_name, "size": 50}}}
            )
            
            for bucket in result.get("aggregations", {}).get("by_event", {}).get("buckets", []):
                event = bucket["key"]
                count = bucket["doc_count"]
                for tech_id in event_mapping.get(event, []):
                    technique_counts[tech_id] = technique_counts.get(tech_id, 0) + count
        except Exception:
            pass
    
    # Build technique list with details including severity
    techniques = []
    for tech_id, tech_info in MITRE_TECHNIQUES.items():
        count = technique_counts.get(tech_id, 0)
        techniques.append({
            "id": tech_id,
            "name": tech_info["name"],
            "tactic": tech_info["tactic"],
            "severity": tech_info.get("severity", "low"),
            "description": tech_info.get("description", ""),
            "url": tech_info.get("url", f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"),
            "count": count,
            "detected": count > 0,
        })
    
    # Sort by count
    techniques.sort(key=lambda x: -x["count"])
    
    # Group by tactic in kill chain order
    tactics_dict = {}
    for tech in techniques:
        tactic = tech["tactic"]
        if tactic not in tactics_dict:
            tactics_dict[tactic] = {"tactic": tactic, "techniques": 0, "total": 0}
        if tech["detected"]:
            tactics_dict[tactic]["techniques"] += 1
        tactics_dict[tactic]["total"] += tech["count"]
    
    # Sort tactics by kill chain order
    tactics_list = []
    for tactic in TACTICS_ORDER:
        if tactic in tactics_dict:
            tactics_list.append(tactics_dict[tactic])
    
    return {
        "techniques": techniques[:20],
        "tactics": tactics_list,
        "summary": {
            "detected": sum(1 for t in techniques if t["detected"]),
            "total": len(techniques),
            "events": sum(technique_counts.values()),
        },
        "time_range": time_range,
    }


@router.get("/mitre/techniques")
async def get_mitre_techniques(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    variant: Optional[str] = None,
    _: str = Depends(get_current_user)
):
    """Get MITRE techniques with evidence from Cowrie commands."""
    from app.services.mitre import MITRE_TECHNIQUES, detect_command_techniques
    
    es = get_es_service()
    
    # Build base query
    must_clauses = [es._get_time_range_query(time_range)]
    if variant:
        must_clauses.append({"term": {"cowrie_variant": variant}})
    
    technique_evidence = {}
    
    # Query for command events using both old and new field schemas
    # Use a "should" query to match either eventid field
    result = await es.search(
        index=INDICES["cowrie"],
        query={
            "bool": {
                "must": must_clauses,
                "should": [
                    {"term": {"json.eventid": "cowrie.command.input"}},
                    {"term": {"cowrie.eventid": "cowrie.command.input"}}
                ],
                "minimum_should_match": 1
            }
        },
        size=0,
        aggs={
            "commands_old": {
                "terms": {"field": "json.input", "size": 100}
            },
            "commands_new": {
                "terms": {"field": "cowrie.input", "size": 100}
            }
        }
    )
    
    # Process commands from both field schemas
    all_commands = {}
    for bucket in result.get("aggregations", {}).get("commands_old", {}).get("buckets", []):
        cmd = bucket["key"]
        count = bucket["doc_count"]
        all_commands[cmd] = all_commands.get(cmd, 0) + count
    
    for bucket in result.get("aggregations", {}).get("commands_new", {}).get("buckets", []):
        cmd = bucket["key"]
        count = bucket["doc_count"]
        all_commands[cmd] = all_commands.get(cmd, 0) + count
    
    # Map commands to MITRE techniques
    for cmd, count in all_commands.items():
        detected_techniques = detect_command_techniques(cmd)
        
        for tech_id in detected_techniques:
            if tech_id not in technique_evidence:
                technique_evidence[tech_id] = {"commands": [], "count": 0}
            if cmd not in technique_evidence[tech_id]["commands"]:
                technique_evidence[tech_id]["commands"].append(cmd)
            technique_evidence[tech_id]["count"] += count
    
    # Build technique list with details
    techniques = []
    for tech_id, evidence in technique_evidence.items():
        if tech_id in MITRE_TECHNIQUES:
            tech_info = MITRE_TECHNIQUES[tech_id]
            techniques.append({
                "id": tech_id,
                "name": tech_info["name"],
                "tactic": tech_info["tactic"],
                "severity": tech_info.get("severity", "low"),
                "description": tech_info.get("description", ""),
                "url": tech_info.get("url", f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"),
                "count": evidence["count"],
                "sample_commands": evidence["commands"][:5],
            })
    
    techniques.sort(key=lambda x: -x["count"])
    
    return {
        "techniques": techniques,
        "time_range": time_range,
    }


# ==================== WEB PATTERNS ====================

@router.get("/web/paths")
async def get_web_paths(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=30, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top URL paths requested."""
    es = get_es_service()
    
    result = await es.search(
        index=INDICES["galah"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "paths": {
                "terms": {"field": "url.path", "size": limit},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}},
                    "methods": {"terms": {"field": "http.request.method", "size": 5}},
                }
            }
        }
    )
    
    paths = []
    for bucket in result.get("aggregations", {}).get("paths", {}).get("buckets", []):
        methods = {b["key"]: b["doc_count"] for b in bucket.get("methods", {}).get("buckets", [])}
        paths.append({
            "path": bucket["key"],
            "count": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0),
            "methods": methods,
        })
    
    return {"paths": paths, "time_range": time_range}


@router.get("/web/useragents")
async def get_web_useragents(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top user agents."""
    es = get_es_service()
    
    result = await es.search(
        index=INDICES["galah"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "useragents": {
                "terms": {"field": "user_agent.original", "size": limit},
                "aggs": {"unique_ips": {"cardinality": {"field": "source.ip"}}}
            }
        }
    )
    
    agents = []
    for bucket in result.get("aggregations", {}).get("useragents", {}).get("buckets", []):
        agents.append({
            "user_agent": bucket["key"],
            "count": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0),
        })
    
    return {"user_agents": agents, "time_range": time_range}


# ==================== MALWARE ====================

@router.get("/malware/summary")
async def get_malware_summary(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get malware capture summary."""
    es = get_es_service()
    
    # Dionaea events
    result = await es.search(
        index=INDICES["dionaea"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_port": {"terms": {"field": "destination.port", "size": 20}},
            "unique_ips": {"cardinality": {"field": "source.ip.keyword"}},
        }
    )
    
    port_names = {445: "SMB", 21: "FTP", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 1433: "MSSQL", 5060: "SIP"}
    ports = []
    for bucket in result.get("aggregations", {}).get("by_port", {}).get("buckets", []):
        port = bucket["key"]
        ports.append({
            "port": port,
            "service": port_names.get(port, f"Unknown"),
            "count": bucket["doc_count"],
        })
    
    # Cowrie downloads
    downloads = 0
    try:
        download_result = await es.search(
            index=INDICES["cowrie"],
            query={
                "bool": {
                    "must": [
                        es._get_time_range_query(time_range),
                        {"term": {"json.eventid": "cowrie.session.file_download"}}
                    ]
                }
            },
            size=0
        )
        downloads = download_result.get("hits", {}).get("total", {}).get("value", 0)
    except Exception:
        pass
    
    return {
        "total_events": result.get("hits", {}).get("total", {}).get("value", 0),
        "unique_attackers": result.get("aggregations", {}).get("unique_ips", {}).get("value", 0),
        "file_downloads": downloads,
        "top_ports": ports,
        "time_range": time_range,
    }


@router.get("/malware/timeline")
async def get_malware_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get malware event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDICES["dionaea"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "timeline": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": interval}
            }
        }
    )
    
    timeline = [
        {"timestamp": bucket["key_as_string"], "count": bucket["doc_count"]}
        for bucket in result.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    ]
    
    return {"timeline": timeline, "interval": interval, "time_range": time_range}


# ==================== AI Performance ====================

@router.get("/ai/latency")
async def get_ai_latency(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get AI response latency metrics by variant."""
    es = get_es_service()
    
    # Query all variants with session and command counts
    result = await es.search(
        index=INDICES["cowrie"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_variant": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    # Support both old and new field structures
                    "sessions_old": {"cardinality": {"field": "json.session"}},
                    "sessions_new": {"cardinality": {"field": "cowrie.session"}},
                    "commands": {"filter": {"bool": {"should": [
                        {"term": {"json.eventid": "cowrie.command.input"}},
                        {"term": {"cowrie.eventid": "cowrie.command.input"}}
                    ], "minimum_should_match": 1}}},
                }
            }
        }
    )
    
    variants = []
    for bucket in result.get("aggregations", {}).get("by_variant", {}).get("buckets", []):
        variant = bucket["key"]
        sessions_old = bucket.get("sessions_old", {}).get("value", 0)
        sessions_new = bucket.get("sessions_new", {}).get("value", 0)
        sessions = max(sessions_old, sessions_new)
        commands = bucket.get("commands", {}).get("doc_count", 0)
        
        variants.append({
            "variant": variant,
            "sessions": sessions,
            "commands": commands,
            # Simulated latency based on variant type
            "latency_p50": 50 if variant == "plain" else (800 if variant == "openai" else 1200),
            "latency_p90": 100 if variant == "plain" else (1500 if variant == "openai" else 2000),
            "latency_p99": 200 if variant == "plain" else (2000 if variant == "openai" else 3000),
        })
    
    return {"variants": variants, "time_range": time_range}


@router.get("/ai/fallback")
async def get_ai_fallback(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get AI fallback rate metrics."""
    # Placeholder - would need actual fallback tracking in the logs
    return {
        "fallback_rate": {
            "openai": 2.5,
            "ollama": 5.8,
        },
        "time_range": time_range,
    }


@router.get("/ai/errors")
async def get_ai_errors(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get AI error rate metrics."""
    # Placeholder - would need actual error tracking in the logs
    return {
        "error_rates": {
            "openai": {"timeout": 0.5, "invalid": 0.1},
            "ollama": {"timeout": 1.2, "invalid": 0.3},
        },
        "time_range": time_range,
    }


# ==================== RDP ====================

@router.get("/rdp/summary")
async def get_rdp_summary(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDP attack summary."""
    es = get_es_service()
    
    result = await es.search(
        index=INDICES["rdpy"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "unique_ips": {"cardinality": {"field": "source.ip"}},
            "countries": {
                "terms": {"field": "source.geo.country_name", "size": 10}
            }
        }
    )
    
    countries = [
        {"country": bucket["key"], "count": bucket["doc_count"]}
        for bucket in result.get("aggregations", {}).get("countries", {}).get("buckets", [])
    ]
    
    return {
        "total_events": result.get("hits", {}).get("total", {}).get("value", 0),
        "unique_attackers": result.get("aggregations", {}).get("unique_ips", {}).get("value", 0),
        "top_countries": countries,
        "time_range": time_range,
    }


@router.get("/rdp/timeline")
async def get_rdp_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get RDP event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDICES["rdpy"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "timeline": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": interval},
                "aggs": {"unique_ips": {"cardinality": {"field": "source.ip"}}}
            }
        }
    )
    
    timeline = [
        {
            "timestamp": bucket["key_as_string"],
            "connections": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0),
        }
        for bucket in result.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    ]
    
    return {"timeline": timeline, "interval": interval, "time_range": time_range}


# ==================== CASE STUDY ====================

@router.get("/case-study/list")
async def list_interesting_sessions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    min_commands: int = Query(default=3, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    variant: Optional[str] = None,
    src_ip: Optional[str] = None,
    _: str = Depends(get_current_user)
):
    """List interesting sessions for case study selection with optional filtering."""
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
    if src_ip:
        must_clauses.append({
            "bool": {
                "should": [
                    {"term": {"json.src_ip": src_ip}},
                    {"term": {"cowrie.src_ip": src_ip}}
                ],
                "minimum_should_match": 1
            }
        })
    
    result = await es.search(
        index=INDICES["cowrie"],
        query={"bool": {"must": must_clauses}},
        size=0,
        aggs={
            "sessions_old": {
                "terms": {"field": "json.session", "size": 500},
                "aggs": {
                    "variant": {"terms": {"field": "cowrie_variant", "size": 1}},
                    "src_ip": {"terms": {"field": "json.src_ip", "size": 1}},
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}},
                }
            },
            "sessions_new": {
                "terms": {"field": "cowrie.session", "size": 500},
                "aggs": {
                    "variant": {"terms": {"field": "cowrie_variant", "size": 1}},
                    "src_ip": {"terms": {"field": "cowrie.src_ip", "size": 1}},
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}},
                }
            }
        }
    )
    
    sessions = []
    # Process both old and new format sessions
    all_session_buckets = (
        result.get("aggregations", {}).get("sessions_old", {}).get("buckets", []) +
        result.get("aggregations", {}).get("sessions_new", {}).get("buckets", [])
    )
    
    for bucket in all_session_buckets:
        cmd_count = bucket["doc_count"]
        if cmd_count < min_commands:
            continue
        
        variant_buckets = bucket.get("variant", {}).get("buckets", [])
        ip_buckets = bucket.get("src_ip", {}).get("buckets", [])
        
        first = bucket.get("first", {}).get("value_as_string")
        last = bucket.get("last", {}).get("value_as_string")
        duration = 0
        if first and last:
            try:
                first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                duration = (last_dt - first_dt).total_seconds()
            except Exception:
                pass
        
        sessions.append({
            "session_id": bucket["key"],
            "variant": variant_buckets[0]["key"] if variant_buckets else None,
            "src_ip": ip_buckets[0]["key"] if ip_buckets else None,
            "commands": cmd_count,
            "duration": round(duration, 2),
            "timestamp": first,
        })
    
    # Sort by command count
    sessions.sort(key=lambda x: -x["commands"])
    
    return {
        "sessions": sessions[:limit],
        "total": len(sessions),
        "time_range": time_range,
    }


@router.get("/case-study/{session_id}")
async def get_case_study(
    session_id: str,
    _: str = Depends(get_current_user)
):
    """Generate case study report for a session."""
    from app.services.mitre import detect_command_techniques, MITRE_TECHNIQUES
    
    es = get_es_service()
    
    # Get all session events - support both old (json.session) and new (cowrie.session) field structures
    result = await es.search(
        index=INDICES["cowrie"],
        query={
            "bool": {
                "should": [
                    {"term": {"json.session": session_id}},
                    {"term": {"cowrie.session": session_id}}
                ],
                "minimum_should_match": 1
            }
        },
        size=1000,
        sort=[{"@timestamp": "asc"}]
    )
    
    events = result.get("hits", {}).get("hits", [])
    if not events:
        return {"error": "Session not found"}
    
    # Extract session metadata
    session_info = {}
    commands = []
    credentials = []
    mitre_techniques = {}
    
    for hit in events:
        source = hit["_source"]
        # Support both old (json.*) and new (cowrie.*) field structures
        json_data = source.get("json", {})
        cowrie_data = source.get("cowrie", {})
        eventid = json_data.get("eventid") or cowrie_data.get("eventid", "")
        
        if "session.connect" in eventid:
            session_info = {
                "src_ip": json_data.get("src_ip") or cowrie_data.get("src_ip"),
                "dst_port": json_data.get("dst_port") or cowrie_data.get("dst_port"),
                "protocol": json_data.get("protocol") or cowrie_data.get("protocol"),
                "sensor": json_data.get("sensor") or cowrie_data.get("sensor"),
                "start_time": source.get("@timestamp"),
            }
        
        if "session.closed" in eventid:
            session_info["end_time"] = source.get("@timestamp")
            session_info["duration"] = json_data.get("duration") or cowrie_data.get("duration")
        
        if "login" in eventid:
            credentials.append({
                "username": json_data.get("username") or cowrie_data.get("username"),
                "password": json_data.get("password") or cowrie_data.get("password"),
                "success": "success" in eventid,
                "timestamp": source.get("@timestamp"),
            })
        
        if "command" in eventid:
            cmd = json_data.get("input") or cowrie_data.get("input", "")
            commands.append({
                "command": cmd,
                "timestamp": source.get("@timestamp"),
            })
            
            # Classify for MITRE
            techniques = detect_command_techniques(cmd)
            for tech_id in techniques:
                if tech_id in MITRE_TECHNIQUES:
                    if tech_id not in mitre_techniques:
                        mitre_techniques[tech_id] = {
                            "id": tech_id,
                            "name": MITRE_TECHNIQUES[tech_id]["name"],
                            "tactic": MITRE_TECHNIQUES[tech_id]["tactic"],
                            "evidence": [],
                        }
                    mitre_techniques[tech_id]["evidence"].append(cmd)
    
    # Get variant
    variant = events[0]["_source"].get("cowrie_variant", "unknown") if events else "unknown"
    
    return {
        "session_id": session_id,
        "variant": variant,
        "info": session_info,
        "commands": commands,
        "credentials": credentials,
        "mitre_techniques": list(mitre_techniques.values()),
        "total_events": len(events),
        "generated_at": datetime.now().isoformat(),
    }


# ==================== FIREWALL ANALYTICS ====================

# Exposed honeypot ports - these are intentionally open
EXPOSED_PORTS = [22, 23, 80, 443, 21, 2222, 3389, 5900, 445, 3306, 1433, 5060]


@router.get("/firewall/overview")
async def get_firewall_overview(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    direction: str = Query(default="in", pattern="^(in|out|all)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall pressure overview with KPIs and charts."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    query = build_firewall_filter_query(time_range, direction)
    
    # Get overall stats
    result = await es.search(
        index=INDICES["firewall"],
        query=query,
        size=0,
        aggs={
            "total": {"value_count": {"field": "@timestamp"}},
            "by_action": {
                "terms": {"field": "fw.action", "size": 10}
            },
            "unique_ips": {"cardinality": {"field": "fw.src_ip"}},
            "top_dst_ports": {
                "filter": {"term": {"fw.action": "block"}},
                "aggs": {
                    "ports": {"terms": {"field": "fw.dst_port", "size": 15}}
                }
            },
            "top_protocols": {
                "terms": {"field": "fw.proto", "size": 10}
            },
            "top_countries": {
                "filter": {"term": {"fw.action": "block"}},
                "aggs": {
                    "countries": {"terms": {"field": "source.geo.country_name", "size": 10}}
                }
            },
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h" if time_range in ["1h", "24h"] else "4h" if time_range == "7d" else "1d"
                },
                "aggs": {
                    "blocked": {"filter": {"term": {"fw.action": "block"}}},
                    "passed": {"filter": {"terms": {"fw.action": ["pass", "nat"]}}}
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    actions = {b["key"]: b["doc_count"] for b in aggs.get("by_action", {}).get("buckets", [])}
    
    blocked = actions.get("block", 0)
    passed = actions.get("pass", 0) + actions.get("nat", 0)
    total = blocked + passed
    
    return {
        "time_range": time_range,
        "direction": direction,
        "kpis": {
            "total_attempts": total,
            "blocked": blocked,
            "allowed": passed,
            "block_rate": round(blocked / total * 100, 1) if total > 0 else 0,
            "unique_ips": aggs.get("unique_ips", {}).get("value", 0),
        },
        "timeline": [
            {
                "timestamp": b["key_as_string"],
                "blocked": b.get("blocked", {}).get("doc_count", 0),
                "allowed": b.get("passed", {}).get("doc_count", 0),
            }
            for b in aggs.get("timeline", {}).get("buckets", [])
        ],
        "top_blocked_ports": [
            {"port": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_dst_ports", {}).get("ports", {}).get("buckets", [])
        ],
        "protocols": [
            {"protocol": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_protocols", {}).get("buckets", [])
        ],
        "top_countries": [
            {"country": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_countries", {}).get("countries", {}).get("buckets", [])
        ],
    }


@router.get("/firewall/closed-ports")
async def get_closed_port_attacks(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    exposed_ports: str = Query(default=",".join(map(str, EXPOSED_PORTS))),
    _: str = Depends(get_current_user)
):
    """Get attacks on closed (non-exposed) ports."""
    es = get_es_service()
    
    # Parse exposed ports
    exposed_list = [int(p.strip()) for p in exposed_ports.split(",") if p.strip().isdigit()]
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    # Query for blocked traffic to non-exposed ports
    result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [
                    time_query,
                    {"term": {"fw.action": "block"}},
                    {"term": {"fw.dir": "in"}}
                ],
                "must_not": [
                    {"terms": {"fw.dst_port": exposed_list}}
                ]
            }
        },
        size=0,
        aggs={
            "total_closed_attacks": {"value_count": {"field": "@timestamp"}},
            "top_closed_ports": {
                "terms": {"field": "fw.dst_port", "size": 20}
            },
            "unique_attackers": {"cardinality": {"field": "fw.src_ip"}},
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h" if time_range in ["1h", "24h"] else "6h"
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    return {
        "time_range": time_range,
        "exposed_ports": exposed_list,
        "total_attacks": aggs.get("total_closed_attacks", {}).get("value", 0),
        "unique_attackers": aggs.get("unique_attackers", {}).get("value", 0),
        "top_closed_ports": [
            {"port": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_closed_ports", {}).get("buckets", [])
        ],
        "timeline": [
            {"timestamp": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs.get("timeline", {}).get("buckets", [])
        ],
    }


@router.get("/firewall/scanners")
async def get_port_scanners(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    window_minutes: int = Query(default=60, ge=5, le=1440),
    min_ports: int = Query(default=20, ge=5),
    min_hits: int = Query(default=50, ge=10),
    _: str = Depends(get_current_user)
):
    """Detect port scanners using heuristics."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    # Get IPs with many distinct ports and high hit counts
    result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [
                    time_query,
                    {"term": {"fw.action": "block"}},
                    {"term": {"fw.dir": "in"}}
                ]
            }
        },
        size=0,
        aggs={
            "by_ip": {
                "terms": {"field": "fw.src_ip", "size": 200},
                "aggs": {
                    "unique_ports": {"cardinality": {"field": "fw.dst_port"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
                    "top_ports": {"terms": {"field": "fw.dst_port", "size": 10}}
                }
            }
        }
    )
    
    scanners = []
    for bucket in result.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        unique_ports = bucket.get("unique_ports", {}).get("value", 0)
        hit_count = bucket["doc_count"]
        
        if unique_ports >= min_ports and hit_count >= min_hits:
            country_buckets = bucket.get("country", {}).get("buckets", [])
            scanners.append({
                "ip": bucket["key"],
                "unique_ports": unique_ports,
                "total_hits": hit_count,
                "first_seen": bucket.get("first_seen", {}).get("value_as_string"),
                "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
                "country": country_buckets[0]["key"] if country_buckets else "Unknown",
                "top_ports": [p["key"] for p in bucket.get("top_ports", {}).get("buckets", [])],
            })
    
    # Sort by unique_ports desc
    scanners.sort(key=lambda x: x["unique_ports"], reverse=True)
    
    return {
        "time_range": time_range,
        "min_ports_threshold": min_ports,
        "min_hits_threshold": min_hits,
        "scanners": scanners[:50],
        "total_detected": len(scanners),
    }


@router.get("/firewall/rules")
async def get_firewall_rules_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall rules hit statistics."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    result = await es.search(
        index=INDICES["firewall"],
        query=time_query,
        size=0,
        aggs={
            "by_rule": {
                "terms": {"field": "fw.rule", "size": 50},
                "aggs": {
                    "by_action": {"terms": {"field": "fw.action", "size": 5}},
                    "by_direction": {"terms": {"field": "fw.dir", "size": 3}},
                }
            }
        }
    )
    
    rules = []
    for bucket in result.get("aggregations", {}).get("by_rule", {}).get("buckets", []):
        actions = {a["key"]: a["doc_count"] for a in bucket.get("by_action", {}).get("buckets", [])}
        directions = {d["key"]: d["doc_count"] for d in bucket.get("by_direction", {}).get("buckets", [])}
        
        rules.append({
            "rule_id": bucket["key"],
            "total_hits": bucket["doc_count"],
            "blocked": actions.get("block", 0),
            "passed": actions.get("pass", 0) + actions.get("nat", 0),
            "inbound": directions.get("in", 0),
            "outbound": directions.get("out", 0),
        })
    
    return {
        "time_range": time_range,
        "rules": rules,
    }


@router.get("/firewall/unexpected-pass")
async def get_unexpected_passes(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    exposed_ports: str = Query(default=",".join(map(str, EXPOSED_PORTS))),
    _: str = Depends(get_current_user)
):
    """Find unexpected inbound passes to non-exposed ports."""
    es = get_es_service()
    
    exposed_list = [int(p.strip()) for p in exposed_ports.split(",") if p.strip().isdigit()]
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [
                    time_query,
                    {"terms": {"fw.action": ["pass", "nat"]}},
                    {"term": {"fw.dir": "in"}}
                ],
                "must_not": [
                    {"terms": {"fw.dst_port": exposed_list}}
                ]
            }
        },
        size=0,
        aggs={
            "total": {"value_count": {"field": "@timestamp"}},
            "by_port": {"terms": {"field": "fw.dst_port", "size": 20}},
            "by_rule": {"terms": {"field": "fw.rule", "size": 10}},
        }
    )
    
    aggs = result.get("aggregations", {})
    
    return {
        "time_range": time_range,
        "exposed_ports": exposed_list,
        "total_unexpected": aggs.get("total", {}).get("value", 0),
        "by_port": [
            {"port": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_port", {}).get("buckets", [])
        ],
        "by_rule": [
            {"rule": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_rule", {}).get("buckets", [])
        ],
    }


@router.get("/firewall/top-attackers-detailed")
async def get_firewall_top_attackers_detailed(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(get_current_user)
):
    """Get detailed top attackers leaderboard."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [time_query, {"term": {"fw.dir": "in"}}]
            }
        },
        size=0,
        aggs={
            "by_ip": {
                "terms": {"field": "fw.src_ip", "size": limit},
                "aggs": {
                    "blocked": {"filter": {"term": {"fw.action": "block"}}},
                    "passed": {"filter": {"terms": {"fw.action": ["pass", "nat"]}}},
                    "unique_ports": {"cardinality": {"field": "fw.dst_port"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
                    "asn": {"terms": {"field": "as.organization.name", "size": 1}},
                    "recent_hits": {
                        "filter": {
                            "range": {
                                "@timestamp": {"gte": "now-1h"}
                            }
                        }
                    }
                }
            }
        }
    )
    
    attackers = []
    for bucket in result.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        total = bucket["doc_count"]
        blocked = bucket.get("blocked", {}).get("doc_count", 0)
        passed = bucket.get("passed", {}).get("doc_count", 0)
        recent = bucket.get("recent_hits", {}).get("doc_count", 0)
        
        country_buckets = bucket.get("country", {}).get("buckets", [])
        asn_buckets = bucket.get("asn", {}).get("buckets", [])
        
        # Calculate burstiness (recent vs average)
        avg_hourly = total / (24 if time_range == "24h" else 168 if time_range == "7d" else 720)
        burstiness = round(recent / avg_hourly, 2) if avg_hourly > 0 else 0
        
        attackers.append({
            "ip": bucket["key"],
            "total_attempts": total,
            "blocked": blocked,
            "passed": passed,
            "block_rate": round(blocked / total * 100, 1) if total > 0 else 0,
            "unique_ports": bucket.get("unique_ports", {}).get("value", 0),
            "first_seen": bucket.get("first_seen", {}).get("value_as_string"),
            "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
            "country": country_buckets[0]["key"] if country_buckets else "Unknown",
            "asn": asn_buckets[0]["key"] if asn_buckets else "Unknown",
            "recent_1h": recent,
            "burstiness": burstiness,
        })
    
    return {
        "time_range": time_range,
        "attackers": attackers,
    }


@router.get("/firewall/attacker/{ip}")
async def get_firewall_attacker_profile(
    ip: str,
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get detailed attacker profile."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [time_query, {"term": {"fw.src_ip": ip}}]
            }
        },
        size=0,
        aggs={
            "total": {"value_count": {"field": "@timestamp"}},
            "by_action": {"terms": {"field": "fw.action", "size": 5}},
            "by_direction": {"terms": {"field": "fw.dir", "size": 3}},
            "top_dst_ports": {"terms": {"field": "fw.dst_port", "size": 20}},
            "top_protocols": {"terms": {"field": "fw.proto", "size": 5}},
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen": {"max": {"field": "@timestamp"}},
            "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
            "city": {"terms": {"field": "source.geo.city_name", "size": 1}},
            "asn": {"terms": {"field": "as.organization.name", "size": 1}},
            "as_number": {"terms": {"field": "as.number", "size": 1}},
            "hourly_pattern": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "hour"
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    actions = {b["key"]: b["doc_count"] for b in aggs.get("by_action", {}).get("buckets", [])}
    
    def get_first_bucket(agg_name):
        buckets = aggs.get(agg_name, {}).get("buckets", [])
        return buckets[0]["key"] if buckets else None
    
    return {
        "ip": ip,
        "time_range": time_range,
        "total_attempts": aggs.get("total", {}).get("value", 0),
        "blocked": actions.get("block", 0),
        "passed": actions.get("pass", 0) + actions.get("nat", 0),
        "first_seen": aggs.get("first_seen", {}).get("value_as_string"),
        "last_seen": aggs.get("last_seen", {}).get("value_as_string"),
        "country": get_first_bucket("country") or "Unknown",
        "city": get_first_bucket("city"),
        "asn": get_first_bucket("asn") or "Unknown",
        "as_number": get_first_bucket("as_number"),
        "top_ports": [
            {"port": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_dst_ports", {}).get("buckets", [])
        ],
        "protocols": [
            {"protocol": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_protocols", {}).get("buckets", [])
        ],
        "hourly_activity": [
            {"timestamp": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs.get("hourly_pattern", {}).get("buckets", [])[-48:]  # Last 48 hours
        ],
    }


@router.get("/firewall/attacker/{ip}/timeline")
async def get_firewall_attacker_timeline(
    ip: str,
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get attacker's activity timeline."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [time_query, {"term": {"fw.src_ip": ip}}]
            }
        },
        size=limit,
        sort=[{"@timestamp": "desc"}],
    )
    
    events = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        fw = source.get("fw", {})
        events.append({
            "timestamp": source.get("@timestamp"),
            "action": fw.get("action"),
            "dst_port": fw.get("dst_port"),
            "protocol": fw.get("proto"),
            "direction": fw.get("dir"),
            "rule": fw.get("rule"),
        })
    
    return {
        "ip": ip,
        "time_range": time_range,
        "events": events,
    }


# ==================== FIREWALL-HONEYPOT CORRELATION ====================

@router.get("/correlation/firewall-honeypot/funnel")
async def get_attack_funnel(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get attack funnel: closed ports -> exposed ports -> authenticated -> commands."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    # Get IPs that hit closed ports (blocked on non-exposed)
    closed_result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [
                    time_query,
                    {"term": {"fw.action": "block"}},
                    {"term": {"fw.dir": "in"}}
                ],
                "must_not": [
                    {"terms": {"fw.dst_port": EXPOSED_PORTS}}
                ]
            }
        },
        size=0,
        aggs={
            "unique_ips": {"cardinality": {"field": "fw.src_ip"}},
            "ips": {"terms": {"field": "fw.src_ip", "size": 10000}}
        }
    )
    
    closed_ips = {b["key"] for b in closed_result.get("aggregations", {}).get("ips", {}).get("buckets", [])}
    closed_count = closed_result.get("aggregations", {}).get("unique_ips", {}).get("value", 0)
    
    # Get IPs that hit exposed ports (from Cowrie) - support both old and new field structures
    exposed_ips = set()
    exposed_count = 0
    for ip_field in ["json.src_ip", "cowrie.src_ip"]:
        cowrie_result = await es.search(
            index=INDICES["cowrie"],
            query=time_query,
            size=0,
            aggs={
                "unique_ips": {"cardinality": {"field": ip_field}},
                "ips": {"terms": {"field": ip_field, "size": 10000}}
            }
        )
        exposed_ips.update(b["key"] for b in cowrie_result.get("aggregations", {}).get("ips", {}).get("buckets", []))
        exposed_count = max(exposed_count, cowrie_result.get("aggregations", {}).get("unique_ips", {}).get("value", 0))
    
    # Get IPs that authenticated - support both field structures
    auth_ips = set()
    auth_count = 0
    for fields in [("json.eventid", "json.src_ip"), ("cowrie.eventid", "cowrie.src_ip")]:
        auth_result = await es.search(
            index=INDICES["cowrie"],
            query={
                "bool": {
                    "must": [
                        time_query,
                        {"term": {fields[0]: "cowrie.login.success"}}
                    ]
                }
            },
            size=0,
            aggs={
                "unique_ips": {"cardinality": {"field": fields[1]}},
                "ips": {"terms": {"field": fields[1], "size": 10000}}
            }
        )
        auth_ips.update(b["key"] for b in auth_result.get("aggregations", {}).get("ips", {}).get("buckets", []))
        auth_count = max(auth_count, auth_result.get("aggregations", {}).get("unique_ips", {}).get("value", 0))
    
    # Get IPs that executed commands - support both field structures
    cmd_ips = set()
    cmd_count = 0
    for fields in [("json.eventid", "json.src_ip"), ("cowrie.eventid", "cowrie.src_ip")]:
        cmd_result = await es.search(
            index=INDICES["cowrie"],
            query={
                "bool": {
                    "must": [
                        time_query,
                        {"term": {fields[0]: "cowrie.command.input"}}
                    ]
                }
            },
            size=0,
            aggs={
                "unique_ips": {"cardinality": {"field": fields[1]}},
                "ips": {"terms": {"field": fields[1], "size": 10000}}
            }
        )
        cmd_ips.update(b["key"] for b in cmd_result.get("aggregations", {}).get("ips", {}).get("buckets", []))
        cmd_count = max(cmd_count, cmd_result.get("aggregations", {}).get("unique_ips", {}).get("value", 0))
    
    # Calculate correlations
    closed_to_exposed = closed_ips & exposed_ips
    closed_to_auth = closed_ips & auth_ips
    closed_to_cmd = closed_ips & cmd_ips
    
    return {
        "time_range": time_range,
        "funnel": {
            "closed_ports": closed_count,
            "exposed_ports": exposed_count,
            "authenticated": auth_count,
            "executed_commands": cmd_count,
        },
        "correlations": {
            "closed_to_exposed": len(closed_to_exposed),
            "closed_to_authenticated": len(closed_to_auth),
            "closed_to_commands": len(closed_to_cmd),
        },
        "conversion_rates": {
            "closed_to_exposed_rate": round(len(closed_to_exposed) / closed_count * 100, 1) if closed_count > 0 else 0,
            "exposed_to_auth_rate": round(auth_count / exposed_count * 100, 1) if exposed_count > 0 else 0,
            "auth_to_cmd_rate": round(cmd_count / auth_count * 100, 1) if auth_count > 0 else 0,
        },
    }


@router.get("/correlation/firewall-honeypot/top")
async def get_correlated_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top attackers that appear in both firewall and honeypot logs."""
    es = get_es_service()
    
    # Use firewall-specific time query with 1-hour offset adjustment
    time_query = get_firewall_time_range_query(time_range)
    
    # Get firewall IPs with stats
    fw_result = await es.search(
        index=INDICES["firewall"],
        query={
            "bool": {
                "must": [time_query, {"term": {"fw.dir": "in"}}]
            }
        },
        size=0,
        aggs={
            "by_ip": {
                "terms": {"field": "fw.src_ip", "size": 500},
                "aggs": {
                    "blocked": {"filter": {"term": {"fw.action": "block"}}},
                    "unique_ports": {"cardinality": {"field": "fw.dst_port"}},
                }
            }
        }
    )
    
    fw_ips = {}
    for bucket in fw_result.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        fw_ips[bucket["key"]] = {
            "fw_total": bucket["doc_count"],
            "fw_blocked": bucket.get("blocked", {}).get("doc_count", 0),
            "fw_ports": bucket.get("unique_ports", {}).get("value", 0),
        }
    
    # Get Cowrie IPs with stats - support both old and new field structures
    cowrie_ips = {}
    for ip_field, session_field, eventid_field in [
        ("json.src_ip", "json.session", "json.eventid"),
        ("cowrie.src_ip", "cowrie.session", "cowrie.eventid")
    ]:
        cowrie_result = await es.search(
            index=INDICES["cowrie"],
            query=time_query,
            size=0,
            aggs={
                "by_ip": {
                    "terms": {"field": ip_field, "size": 500},
                    "aggs": {
                        "sessions": {"cardinality": {"field": session_field}},
                        "commands": {"filter": {"term": {eventid_field: "cowrie.command.input"}}},
                        "logins": {"filter": {"prefix": {eventid_field: "cowrie.login"}}},
                    }
                }
            }
        )
        
        for bucket in cowrie_result.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
            ip = bucket["key"]
            if ip not in cowrie_ips:
                cowrie_ips[ip] = {
                    "cowrie_events": 0,
                    "cowrie_sessions": 0,
                    "cowrie_commands": 0,
                    "cowrie_logins": 0,
                }
            cowrie_ips[ip]["cowrie_events"] += bucket["doc_count"]
            cowrie_ips[ip]["cowrie_sessions"] = max(cowrie_ips[ip]["cowrie_sessions"], bucket.get("sessions", {}).get("value", 0))
            cowrie_ips[ip]["cowrie_commands"] += bucket.get("commands", {}).get("doc_count", 0)
            cowrie_ips[ip]["cowrie_logins"] += bucket.get("logins", {}).get("doc_count", 0)
    
    # Find IPs in both
    common_ips = set(fw_ips.keys()) & set(cowrie_ips.keys())
    
    correlated = []
    for ip in common_ips:
        correlated.append({
            "ip": ip,
            **fw_ips[ip],
            **cowrie_ips[ip],
        })
    
    # Sort by total activity
    correlated.sort(key=lambda x: x["fw_total"] + x["cowrie_events"], reverse=True)
    
    return {
        "time_range": time_range,
        "attackers": correlated[:limit],
        "total_correlated": len(correlated),
    }


# ==================== GALAH CONVERSATIONS ====================

@router.get("/galah/conversations")
async def get_galah_conversations(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=30, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get Galah LLM conversation summaries."""
    es = get_es_service()
    
    time_query = build_filter_query(time_range)["bool"]["must"][0]
    
    result = await es.search(
        index=INDICES["galah"],
        query=time_query,
        size=limit,
        sort=[{"@timestamp": "desc"}],
    )
    
    conversations = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        conversations.append({
            "id": hit["_id"],
            "timestamp": source.get("@timestamp"),
            "src_ip": source.get("source", {}).get("ip"),
            "method": source.get("http", {}).get("request", {}).get("method"),
            "path": source.get("url", {}).get("path"),
            "user_agent": source.get("user_agent", {}).get("original", "")[:100],
            "response_status": source.get("http", {}).get("response", {}).get("status_code"),
            "duration_ms": source.get("event", {}).get("duration"),
            "msg": source.get("msg", ""),
            "country": source.get("source", {}).get("geo", {}).get("country_name"),
        })
    
    return {
        "time_range": time_range,
        "conversations": conversations,
    }


@router.get("/galah/conversation/{conversation_id}")
async def get_galah_conversation_detail(
    conversation_id: str,
    _: str = Depends(get_current_user)
):
    """Get detailed Galah conversation including request/response."""
    es = get_es_service()
    
    result = await es.search(
        index=INDICES["galah"],
        query={"term": {"_id": conversation_id}},
        size=1,
    )
    
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return {"error": "Conversation not found"}
    
    source = hits[0]["_source"]
    
    return {
        "id": conversation_id,
        "timestamp": source.get("@timestamp"),
        "source": {
            "ip": source.get("source", {}).get("ip"),
            "geo": source.get("source", {}).get("geo", {}),
        },
        "request": {
            "method": source.get("http", {}).get("request", {}).get("method"),
            "path": source.get("url", {}).get("path"),
            "query": source.get("url", {}).get("query"),
            "headers": source.get("http", {}).get("request", {}).get("headers", {}),
            "body": source.get("http", {}).get("request", {}).get("body", {}).get("content"),
        },
        "response": {
            "status": source.get("http", {}).get("response", {}).get("status_code"),
            "headers": source.get("http", {}).get("response", {}).get("headers", {}),
            "body": source.get("http", {}).get("response", {}).get("body", {}).get("content"),
        },
        "user_agent": source.get("user_agent", {}),
        "duration_ms": source.get("event", {}).get("duration"),
        "msg": source.get("msg"),
    }


# ==================== ATTACK SURFACE ANALYSIS ====================

@router.get("/attack-surface/ports")
async def get_attack_surface_ports(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """
    Get most targeted ports from firewall blocked/denied logs.
    Shows which ports attackers are actually scanning.
    """
    es = get_es_service()
    time_query = get_firewall_time_range_query(time_range)
    
    # Query blocked traffic - destination ports
    result = await es.search(
        index=INDICES["firewall"],
        query={"bool": {"must": [
            time_query,
            {"term": {"event.action": "block"}}
        ]}},
        size=0,
        aggs={
            "ports": {
                "terms": {"field": "destination.port", "size": limit},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}},
                    "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 5}}
                }
            },
            "total_blocked": {"value_count": {"field": "@timestamp"}}
        }
    )
    
    ports = []
    for bucket in result.get("aggregations", {}).get("ports", {}).get("buckets", []):
        top_countries = [c["key"] for c in bucket.get("countries", {}).get("buckets", [])]
        ports.append({
            "port": bucket["key"],
            "hits": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0),
            "top_countries": top_countries,
            "service": get_port_service(bucket["key"])
        })
    
    return {
        "ports": ports,
        "total_blocked": result.get("aggregations", {}).get("total_blocked", {}).get("value", 0),
        "time_range": time_range
    }


def get_port_service(port: int) -> str:
    """Map common ports to service names."""
    services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
        445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1434: "MSSQL-UDP", 1521: "Oracle", 2222: "SSH-Alt",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    return services.get(port, f"Port-{port}")


@router.get("/attack-surface/scanners")
async def get_attack_surface_scanners(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    min_ports: int = Query(default=5, ge=2, le=50),
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(get_current_user)
):
    """
    Detect port scanners: IPs that hit multiple ports in a short time.
    Identifies masscan/nmap/zmap patterns.
    """
    es = get_es_service()
    time_query = get_firewall_time_range_query(time_range)
    
    # Find IPs hitting multiple destination ports
    result = await es.search(
        index=INDICES["firewall"],
        query={"bool": {"must": [time_query]}},
        size=0,
        aggs={
            "scanners": {
                "terms": {"field": "source.ip", "size": 500},
                "aggs": {
                    "ports_scanned": {"cardinality": {"field": "destination.port"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "port_list": {"terms": {"field": "destination.port", "size": 20}},
                    "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
                    "blocked": {"filter": {"term": {"event.action": "block"}}},
                    "passed": {"filter": {"term": {"event.action": "pass"}}}
                }
            }
        }
    )
    
    scanners = []
    for bucket in result.get("aggregations", {}).get("scanners", {}).get("buckets", []):
        ports_count = bucket.get("ports_scanned", {}).get("value", 0)
        if ports_count < min_ports:
            continue
        
        first_seen = bucket.get("first_seen", {}).get("value_as_string", "")
        last_seen = bucket.get("last_seen", {}).get("value_as_string", "")
        
        # Calculate scan duration
        duration_sec = 0
        if first_seen and last_seen:
            try:
                first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                duration_sec = (last_dt - first_dt).total_seconds()
            except:
                pass
        
        port_list = [p["key"] for p in bucket.get("port_list", {}).get("buckets", [])]
        countries = bucket.get("country", {}).get("buckets", [])
        
        # Classify scanner type based on behavior
        events = bucket["doc_count"]
        scan_rate = events / duration_sec if duration_sec > 0 else events
        
        if scan_rate > 100:
            scanner_type = "masscan"
        elif scan_rate > 10:
            scanner_type = "nmap-fast"
        elif ports_count > 100:
            scanner_type = "full-scan"
        else:
            scanner_type = "targeted"
        
        scanners.append({
            "ip": bucket["key"],
            "total_events": events,
            "ports_scanned": ports_count,
            "blocked": bucket.get("blocked", {}).get("doc_count", 0),
            "passed": bucket.get("passed", {}).get("doc_count", 0),
            "duration_sec": round(duration_sec, 1),
            "scan_rate": round(scan_rate, 2),
            "scanner_type": scanner_type,
            "port_sample": port_list[:10],
            "country": countries[0]["key"] if countries else None,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })
    
    # Sort by ports scanned
    scanners.sort(key=lambda x: -x["ports_scanned"])
    
    return {
        "scanners": scanners[:limit],
        "total_detected": len(scanners),
        "time_range": time_range
    }


@router.get("/attack-surface/by-sensor")
async def get_attack_surface_by_sensor(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Distribution of attacks by destination IP (WAN IP / sensor).
    Shows how attack patterns differ based on exposed services.
    """
    es = get_es_service()
    time_query = get_firewall_time_range_query(time_range)
    
    # Aggregate by destination IP
    result = await es.search(
        index=INDICES["firewall"],
        query={"bool": {"must": [time_query]}},
        size=0,
        aggs={
            "sensors": {
                "terms": {"field": "destination.ip", "size": 20},
                "aggs": {
                    "unique_attackers": {"cardinality": {"field": "source.ip"}},
                    "top_ports": {"terms": {"field": "destination.port", "size": 10}},
                    "blocked": {"filter": {"term": {"event.action": "block"}}},
                    "passed": {"filter": {"term": {"event.action": "pass"}}},
                    "countries": {"terms": {"field": "source.geo.country_name", "size": 5}}
                }
            }
        }
    )
    
    sensors = []
    for bucket in result.get("aggregations", {}).get("sensors", {}).get("buckets", []):
        top_ports = [
            {"port": p["key"], "hits": p["doc_count"], "service": get_port_service(p["key"])}
            for p in bucket.get("top_ports", {}).get("buckets", [])
        ]
        top_countries = [c["key"] for c in bucket.get("countries", {}).get("buckets", [])]
        
        sensors.append({
            "ip": bucket["key"],
            "total_events": bucket["doc_count"],
            "unique_attackers": bucket.get("unique_attackers", {}).get("value", 0),
            "blocked": bucket.get("blocked", {}).get("doc_count", 0),
            "passed": bucket.get("passed", {}).get("doc_count", 0),
            "top_ports": top_ports,
            "top_countries": top_countries,
        })
    
    return {
        "sensors": sensors,
        "time_range": time_range
    }


@router.get("/attack-surface/heatmap")
async def get_attack_surface_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Temporal heatmap: attacks by hour and day of week.
    Identifies attack patterns (night peaks, weekend campaigns).
    """
    es = get_es_service()
    time_query = get_firewall_time_range_query(time_range)
    
    # Use date_histogram with hour interval
    result = await es.search(
        index=INDICES["firewall"],
        query={"bool": {"must": [time_query]}},
        size=0,
        aggs={
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "hour"
                },
                "aggs": {
                    "blocked": {"filter": {"term": {"event.action": "block"}}}
                }
            }
        }
    )
    
    # Process into heatmap format (day x hour)
    heatmap = {}  # {day_of_week: {hour: count}}
    hourly_totals = [0] * 24
    daily_totals = [0] * 7
    
    for bucket in result.get("aggregations", {}).get("by_hour", {}).get("buckets", []):
        ts = bucket.get("key_as_string", "")
        count = bucket["doc_count"]
        blocked = bucket.get("blocked", {}).get("doc_count", 0)
        
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                dow = dt.weekday()  # 0=Monday, 6=Sunday
                hour = dt.hour
                
                if dow not in heatmap:
                    heatmap[dow] = {}
                if hour not in heatmap[dow]:
                    heatmap[dow][hour] = {"total": 0, "blocked": 0}
                
                heatmap[dow][hour]["total"] += count
                heatmap[dow][hour]["blocked"] += blocked
                hourly_totals[hour] += count
                daily_totals[dow] += count
            except:
                pass
    
    # Convert to grid format
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    grid = []
    for hour in range(24):
        row = {"hour": hour}
        for dow in range(7):
            cell = heatmap.get(dow, {}).get(hour, {"total": 0, "blocked": 0})
            row[days[dow]] = cell["total"]
        grid.append(row)
    
    # Find peak times
    peak_hour = max(range(24), key=lambda h: hourly_totals[h])
    peak_day = max(range(7), key=lambda d: daily_totals[d])
    
    return {
        "grid": grid,
        "hourly_totals": hourly_totals,
        "daily_totals": dict(zip(days, daily_totals)),
        "peak_hour": peak_hour,
        "peak_day": days[peak_day],
        "time_range": time_range
    }


@router.get("/attack-surface/open-vs-attacked")
async def get_open_vs_attacked(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Compare open ports (honeypot services) vs attacked ports.
    Shows discrepancy between what's exposed and what's targeted.
    """
    es = get_es_service()
    time_query = get_firewall_time_range_query(time_range)
    
    # Get attacked ports from firewall
    fw_result = await es.search(
        index=INDICES["firewall"],
        query={"bool": {"must": [time_query]}},
        size=0,
        aggs={
            "blocked_ports": {
                "filter": {"term": {"event.action": "block"}},
                "aggs": {
                    "ports": {"terms": {"field": "destination.port", "size": 100}}
                }
            },
            "passed_ports": {
                "filter": {"term": {"event.action": "pass"}},
                "aggs": {
                    "ports": {"terms": {"field": "destination.port", "size": 100}}
                }
            }
        }
    )
    
    # Define known open ports (honeypot services)
    open_ports = {
        22: {"service": "SSH (Cowrie)", "honeypot": "cowrie"},
        23: {"service": "Telnet", "honeypot": "cowrie"},
        80: {"service": "HTTP (Galah)", "honeypot": "galah"},
        443: {"service": "HTTPS (Galah)", "honeypot": "galah"},
        3389: {"service": "RDP (RDPY)", "honeypot": "rdpy"},
        21: {"service": "FTP (Dionaea)", "honeypot": "dionaea"},
        445: {"service": "SMB (Dionaea)", "honeypot": "dionaea"},
        1433: {"service": "MSSQL (Dionaea)", "honeypot": "dionaea"},
        3306: {"service": "MySQL (Dionaea)", "honeypot": "dionaea"},
    }
    
    # Build attacked ports map
    attacked_blocked = {}
    for bucket in fw_result.get("aggregations", {}).get("blocked_ports", {}).get("ports", {}).get("buckets", []):
        attacked_blocked[bucket["key"]] = bucket["doc_count"]
    
    attacked_passed = {}
    for bucket in fw_result.get("aggregations", {}).get("passed_ports", {}).get("ports", {}).get("buckets", []):
        attacked_passed[bucket["key"]] = bucket["doc_count"]
    
    # Combine data
    comparison = []
    all_ports = set(open_ports.keys()) | set(attacked_blocked.keys()) | set(attacked_passed.keys())
    
    for port in sorted(all_ports)[:50]:  # Top 50
        is_open = port in open_ports
        blocked = attacked_blocked.get(port, 0)
        passed = attacked_passed.get(port, 0)
        total = blocked + passed
        
        comparison.append({
            "port": port,
            "service": open_ports.get(port, {}).get("service") or get_port_service(port),
            "honeypot": open_ports.get(port, {}).get("honeypot"),
            "is_open": is_open,
            "blocked": blocked,
            "passed": passed,
            "total_attacks": total,
            "block_rate": round((blocked / total) * 100, 1) if total > 0 else 0,
        })
    
    # Sort by total attacks
    comparison.sort(key=lambda x: -x["total_attacks"])
    
    # Summary stats
    open_port_attacks = sum(c["total_attacks"] for c in comparison if c["is_open"])
    closed_port_attacks = sum(c["total_attacks"] for c in comparison if not c["is_open"])
    
    return {
        "comparison": comparison[:30],
        "summary": {
            "open_ports": len(open_ports),
            "attacked_open": open_port_attacks,
            "attacked_closed": closed_port_attacks,
            "total_unique_attacked_ports": len(all_ports),
        },
        "time_range": time_range
    }


@router.get("/attack-surface/timeline")
async def get_attack_surface_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Time series of attacks across all sensors and firewall.
    """
    es = get_es_service()
    time_query = get_firewall_time_range_query(time_range)
    
    # Determine interval based on time range
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDICES["firewall"],
        query={"bool": {"must": [time_query]}},
        size=0,
        aggs={
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval
                },
                "aggs": {
                    "blocked": {"filter": {"term": {"event.action": "block"}}},
                    "passed": {"filter": {"term": {"event.action": "pass"}}},
                    "unique_ips": {"cardinality": {"field": "source.ip"}}
                }
            }
        }
    )
    
    timeline = []
    for bucket in result.get("aggregations", {}).get("timeline", {}).get("buckets", []):
        timeline.append({
            "timestamp": bucket["key_as_string"],
            "total": bucket["doc_count"],
            "blocked": bucket.get("blocked", {}).get("doc_count", 0),
            "passed": bucket.get("passed", {}).get("doc_count", 0),
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0),
        })
    
    return {
        "timeline": timeline,
        "interval": interval,
        "time_range": time_range
    }
