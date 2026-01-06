"""Attacker profile API routes."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service
from app.models.schemas import (
    AttackerProfile,
    HoneypotActivity,
    CowrieCredential,
)

router = APIRouter()


def extract_geo_from_event(event: dict, honeypot: str) -> Optional[str]:
    """Extract country from event based on honeypot type."""
    # All honeypots now use source.geo for GeoIP (if enriched)
    return event.get("source", {}).get("geo", {}).get("country_name")


def extract_src_ip_from_event(event: dict, honeypot: str) -> Optional[str]:
    """Extract source IP from event based on honeypot type."""
    if honeypot == "cowrie":
        # Support both old (json.src_ip) and new (cowrie.src_ip) field structures
        return event.get("json", {}).get("src_ip") or event.get("cowrie", {}).get("src_ip")
    else:
        return event.get("source", {}).get("ip")


@router.get("/{ip}", response_model=AttackerProfile)
async def get_attacker_profile(
    ip: str,
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get comprehensive attacker profile across all honeypots.
    
    Returns:
    - Total events
    - First and last seen timestamps
    - Countries (if IP appeared from multiple locations)
    - Activity breakdown by honeypot
    - Credentials attempted (if available)
    - Commands executed (if available)
    """
    es = get_es_service()
    
    # Get accurate event counts per honeypot using count API
    honeypot_event_counts = await es.get_event_counts_for_ip(ip, time_range=time_range)
    
    # Get sample events for this IP across all honeypots (limited for details)
    events_by_honeypot = await es.get_events_for_ip(ip, time_range=time_range, size=500)
    
    if not events_by_honeypot and not honeypot_event_counts:
        raise HTTPException(status_code=404, detail=f"No events found for IP {ip}")
    
    # Aggregate data
    total_events = sum(honeypot_event_counts.values())
    all_timestamps = []
    countries = set()
    honeypot_activity = []
    credentials_tried = []
    commands_executed = []
    all_session_durations = []
    
    for honeypot, events in events_by_honeypot.items():
        # Use actual count from aggregation, not len(events)
        actual_event_count = honeypot_event_counts.get(honeypot, len(events))
        
        # Track sessions for this honeypot
        sessions = {}
        
        # Extract timestamps
        timestamps = []
        for event in events:
            ts = event.get("@timestamp")
            if ts:
                timestamps.append(ts)
                all_timestamps.append(ts)
            
            # Extract country based on honeypot type
            country = extract_geo_from_event(event, honeypot)
            if country:
                countries.add(country)
            
            # Track session for duration calculation
            session_id = None
            if honeypot == "cowrie":
                # Support both cowrie.* and json.* field structures
                session_id = event.get("cowrie", {}).get("session") or event.get("json", {}).get("session")
            elif honeypot == "galah":
                session_id = event.get("session", {}).get("id")
            elif honeypot == "heralding":
                session_id = event.get("session_id")
            
            if session_id and ts:
                if session_id not in sessions:
                    sessions[session_id] = {"first": ts, "last": ts}
                else:
                    if ts < sessions[session_id]["first"]:
                        sessions[session_id]["first"] = ts
                    if ts > sessions[session_id]["last"]:
                        sessions[session_id]["last"] = ts
            
            # Extract credentials based on honeypot type
            if honeypot == "cowrie":
                # Support both cowrie.* and json.* field structures
                cowrie = event.get("cowrie", {}) or {}
                json_data = event.get("json", {}) or {}
                
                username = cowrie.get("username") or json_data.get("username")
                password = cowrie.get("password") or json_data.get("password")
                if username:
                    credentials_tried.append({
                        "username": username,
                        "password": password or ""
                    })
                
                # Extract commands - check both field structures
                eventid = cowrie.get("eventid") or json_data.get("eventid")
                if eventid == "cowrie.command.input":
                    command = cowrie.get("input") or json_data.get("input")
                    if command:
                        commands_executed.append(command)
            
            elif honeypot == "heralding":
                user = event.get("user", {})
                username = user.get("name")
                password = user.get("password", "")
                if username:
                    credentials_tried.append({
                        "username": username,
                        "password": password
                    })
            
            elif honeypot == "rdpy":
                user = event.get("user", {})
                username = user.get("name")
                if username:
                    credentials_tried.append({
                        "username": username,
                        "password": ""
                    })
        
        # Calculate session durations for this honeypot
        honeypot_duration = 0.0
        honeypot_session_count = len(sessions)
        for sess_id, sess_times in sessions.items():
            try:
                first_dt = datetime.fromisoformat(sess_times["first"].replace("Z", "+00:00"))
                last_dt = datetime.fromisoformat(sess_times["last"].replace("Z", "+00:00"))
                duration = (last_dt - first_dt).total_seconds()
                honeypot_duration += duration
                all_session_durations.append(duration)
            except:
                pass
        
        if timestamps:
            timestamps.sort()
            honeypot_activity.append(HoneypotActivity(
                honeypot=honeypot,
                event_count=actual_event_count,  # Use actual count, not len(events)
                first_seen=timestamps[0],
                last_seen=timestamps[-1],
                duration_seconds=round(honeypot_duration, 2) if honeypot_duration else None,
                session_count=honeypot_session_count if honeypot_session_count else None
            ))
    
    # Sort all timestamps
    all_timestamps.sort()
    
    # Deduplicate and count credentials
    cred_counts = {}
    for cred in credentials_tried:
        key = (cred["username"], cred["password"])
        cred_counts[key] = cred_counts.get(key, 0) + 1
    
    unique_credentials = [
        CowrieCredential(
            username=k[0],
            password=k[1],
            count=v,
            success=False
        )
        for k, v in sorted(cred_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    ]
    
    # Deduplicate commands
    unique_commands = list(set(commands_executed))[:50]
    
    # Calculate total duration metrics
    total_duration = sum(all_session_durations) if all_session_durations else None
    session_count = len(all_session_durations) if all_session_durations else None
    avg_session_duration = (total_duration / session_count) if session_count and total_duration else None
    
    # Classify behavior: Script (fast, <5s avg), Human (longer sessions), Bot (repetitive)
    behavior = None
    if avg_session_duration is not None:
        if avg_session_duration < 5:
            behavior = "Script"  # Fast automated attacks
        elif avg_session_duration > 60:
            behavior = "Human"  # Longer exploratory sessions
        else:
            behavior = "Bot"  # Moderate duration, likely automated but interactive
    
    return AttackerProfile(
        ip=ip,
        total_events=total_events,
        first_seen=all_timestamps[0] if all_timestamps else "",
        last_seen=all_timestamps[-1] if all_timestamps else "",
        countries=list(countries),
        honeypot_activity=honeypot_activity,
        credentials_tried=unique_credentials if unique_credentials else None,
        commands_executed=unique_commands if unique_commands else None,
        total_duration_seconds=round(total_duration, 2) if total_duration else None,
        avg_session_duration=round(avg_session_duration, 2) if avg_session_duration else None,
        session_count=session_count,
        behavior_classification=behavior
    )


@router.get("/{ip}/timeline")
async def get_attacker_timeline(
    ip: str,
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=1000),
    _: str = Depends(get_current_user)
):
    """
    Get unified timeline of attacker activity across all honeypots.
    """
    es = get_es_service()
    
    events_by_honeypot = await es.get_events_for_ip(ip, time_range=time_range, size=limit)
    
    # Flatten and sort by timestamp
    all_events = []
    for honeypot, events in events_by_honeypot.items():
        for event in events:
            event["_honeypot"] = honeypot
            all_events.append(event)
    
    # Sort by timestamp
    all_events.sort(key=lambda x: x.get("@timestamp", ""), reverse=True)
    
    # Format for display
    timeline = []
    for event in all_events[:limit]:
        honeypot = event.get("_honeypot")
        
        entry = {
            "timestamp": event.get("@timestamp"),
            "honeypot": honeypot,
            "event_type": "unknown",
            "detail": "",
        }
        
        # Add relevant details based on honeypot type
        if honeypot == "cowrie":
            cowrie = event.get("cowrie", {})
            entry["event_type"] = cowrie.get("eventid", "unknown")
            
            if cowrie.get("input"):
                entry["detail"] = f"Command: {cowrie['input']}"
            elif cowrie.get("username"):
                entry["detail"] = f"Login attempt: {cowrie['username']}"
            elif cowrie.get("eventid"):
                entry["detail"] = cowrie.get("eventid", "")
        
        elif honeypot == "galah":
            method = event.get("http", {}).get("request", {}).get("method", "GET")
            uri = event.get("url", {}).get("path", "/")
            entry["event_type"] = event.get("msg", "request")
            entry["detail"] = f"{method} {uri}"
        
        elif honeypot == "dionaea":
            dionaea = event.get("dionaea", {})
            transport = event.get("network", {}).get("transport", "")
            port = event.get("destination", {}).get("port", "")
            entry["event_type"] = dionaea.get("component", "connection")
            entry["detail"] = f"{transport}:{port}" if port else dionaea.get("msg", "")[:100]
        
        elif honeypot == "rdpy":
            user = event.get("user", {})
            username = user.get("name", "")
            domain = user.get("domain", "")
            entry["event_type"] = "rdp_connection"
            entry["detail"] = f"RDP: {domain}\\{username}" if domain else f"RDP: {username}"
        
        elif honeypot == "heralding":
            protocol = event.get("network", {}).get("protocol", "")
            user = event.get("user", {})
            username = user.get("name", "")
            entry["event_type"] = f"{protocol}_session"
            entry["detail"] = f"{protocol}: {username}" if username else protocol
        
        elif honeypot == "firewall":
            fw = event.get("fw", {})
            action = fw.get("action", "")
            port = event.get("destination", {}).get("port", "")
            entry["event_type"] = action
            entry["detail"] = f"{action} port {port}"
        
        timeline.append(entry)
    
    return {"ip": ip, "timeline": timeline, "time_range": time_range}


@router.get("/{ip}/sessions")
async def get_attacker_sessions(
    ip: str,
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get session-based view of attacker activity.
    Groups events by session ID where applicable.
    """
    es = get_es_service()
    
    events_by_honeypot = await es.get_events_for_ip(ip, time_range=time_range, size=500)
    
    sessions = {}
    
    for honeypot, events in events_by_honeypot.items():
        for event in events:
            # Extract session ID based on honeypot type
            if honeypot == "cowrie":
                session_id = event.get("cowrie", {}).get("session")
            elif honeypot == "galah":
                session_id = event.get("session", {}).get("id")
            elif honeypot == "heralding":
                session_id = event.get("session_id")
            else:
                session_id = None
            
            if session_id:
                if session_id not in sessions:
                    sessions[session_id] = {
                        "session_id": session_id,
                        "honeypot": honeypot,
                        "events": [],
                        "first_seen": None,
                        "last_seen": None,
                    }
                
                sessions[session_id]["events"].append({
                    "timestamp": event.get("@timestamp"),
                    "event_type": event.get("cowrie", {}).get("eventid") or event.get("msg") or "event",
                })
                
                ts = event.get("@timestamp", "")
                if not sessions[session_id]["first_seen"] or ts < sessions[session_id]["first_seen"]:
                    sessions[session_id]["first_seen"] = ts
                if not sessions[session_id]["last_seen"] or ts > sessions[session_id]["last_seen"]:
                    sessions[session_id]["last_seen"] = ts
    
    # Convert to list and add event counts
    session_list = []
    for session_id, session_data in sessions.items():
        session_data["event_count"] = len(session_data["events"])
        session_data["events"] = sorted(session_data["events"], key=lambda x: x["timestamp"])
        session_list.append(session_data)
    
    # Sort by first_seen
    session_list.sort(key=lambda x: x["first_seen"] or "", reverse=True)
    
    return {"ip": ip, "sessions": session_list, "time_range": time_range}


@router.get("/{ip}/raw")
async def get_attacker_raw_logs(
    ip: str,
    honeypot: Optional[str] = Query(default=None),
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=1000),
    _: str = Depends(get_current_user)
):
    """
    Get raw log entries for an attacker.
    Optionally filter by honeypot type.
    """
    es = get_es_service()
    
    indices = None
    if honeypot:
        if honeypot in es.INDICES:
            indices = [es.INDICES[honeypot]]
        else:
            raise HTTPException(status_code=400, detail=f"Unknown honeypot: {honeypot}")
    
    events_by_honeypot = await es.get_events_for_ip(ip, indices=indices, time_range=time_range, size=limit)
    
    # Flatten all events
    all_events = []
    for hp, events in events_by_honeypot.items():
        for event in events:
            all_events.append({
                "honeypot": hp,
                "timestamp": event.get("@timestamp"),
                "raw": event,
            })
    
    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    
    return {
        "ip": ip,
        "total": len(all_events),
        "logs": all_events[:limit],
        "time_range": time_range
    }


@router.get("/{ip}/export")
async def export_attacker_data(
    ip: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Export attacker data in JSON or CSV format.
    """
    es = get_es_service()
    
    events_by_honeypot = await es.get_events_for_ip(ip, time_range=time_range, size=10000)
    
    if format == "json":
        return {
            "ip": ip,
            "time_range": time_range,
            "exported_at": datetime.utcnow().isoformat(),
            "events": events_by_honeypot
        }
    
    elif format == "csv":
        # Flatten events for CSV
        rows = []
        for honeypot, events in events_by_honeypot.items():
            for event in events:
                # Extract fields based on honeypot type
                if honeypot == "cowrie":
                    cowrie = event.get("cowrie", {})
                    row = {
                        "honeypot": honeypot,
                        "timestamp": event.get("@timestamp", ""),
                        "src_ip": cowrie.get("src_ip", ""),
                        "event_type": cowrie.get("eventid", ""),
                        "session": cowrie.get("session", ""),
                        "username": cowrie.get("username", ""),
                        "password": cowrie.get("password", ""),
                        "command": cowrie.get("input", ""),
                        "country": cowrie.get("geo", {}).get("country_name", ""),
                    }
                else:
                    row = {
                        "honeypot": honeypot,
                        "timestamp": event.get("@timestamp", ""),
                        "src_ip": event.get("source", {}).get("ip", ""),
                        "event_type": event.get("msg", "") or event.get("dionaea", {}).get("component", ""),
                        "session": event.get("session_id", "") or event.get("session", {}).get("id", ""),
                        "username": event.get("user", {}).get("name", ""),
                        "password": "",
                        "command": "",
                        "country": event.get("source", {}).get("geo", {}).get("country_name", ""),
                    }
                rows.append(row)
        
        # Sort by timestamp
        rows.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Generate CSV content
        if not rows:
            return {"content": "", "filename": f"attacker_{ip}.csv"}
        
        headers = list(rows[0].keys())
        csv_lines = [",".join(headers)]
        
        for row in rows:
            values = [str(row.get(h, "")).replace(",", ";").replace("\n", " ") for h in headers]
            csv_lines.append(",".join(values))
        
        return {
            "content": "\n".join(csv_lines),
            "filename": f"attacker_{ip.replace('.', '_')}.csv"
        }


# Honeypot indices and colors for country-based endpoints
HONEYPOT_INDICES = {
    "cowrie": ".ds-cowrie-*",
    "dionaea": "dionaea-*",
    "galah": ".ds-galah-*",
    "rdpy": ".ds-rdpy-*",
    "heralding": ".ds-heralding-*",
    "firewall": "filebeat-*",
}

# Firewall logs have a 1-hour timezone offset
FIREWALL_TIMEZONE_OFFSET_HOURS = 1

HONEYPOT_COLORS = {
    "cowrie": "#39ff14",
    "dionaea": "#00d4ff",
    "firewall": "#ffd700",
    "galah": "#ff6600",
    "rdpy": "#bf00ff",
    "heralding": "#ff3366",
}


@router.get("/countries/list")
async def get_attackers_by_country(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get attacker statistics grouped by country.
    
    Uses unified global stats for consistent numbers with Dashboard.
    Excludes firewall to match honeypot-focused view.
    """
    es = get_es_service()
    
    # Use unified global stats (same as Dashboard) for consistency
    global_stats = await es.get_global_stats(time_range)
    
    # Get country breakdown with per-honeypot data
    # Exclude firewall to focus on honeypots only
    country_data = {}
    honeypot_indices = {k: v for k, v in es.INDICES.items() if k != "firewall"}
    
    for honeypot, index in honeypot_indices.items():
        is_firewall = False
        time_query = es._get_time_range_query(time_range, is_firewall=is_firewall)
        
        # Build query with proper filters
        must_clauses = [time_query]
        must_clauses.extend(es._get_base_filter(index))
        
        must_not_clauses = es._get_internal_ip_exclusion(index)
        if honeypot == "dionaea":
            must_not_clauses.extend(es._get_dionaea_noise_exclusion())
        
        query = {"bool": {"must": must_clauses, "must_not": must_not_clauses}}
        
        # Get the right field names
        # For Cowrie, we need to try multiple possible geo fields
        if honeypot == "cowrie":
            # Cowrie may have geo data in different locations depending on pipeline
            country_fields = [
                "source.geo.country_name",      # Standard ECS location
                "cowrie.geo.country_name",      # Cowrie-specific namespace
                "source.geo.country_name.keyword",  # Keyword variant
            ]
            ip_fields = ["json.src_ip", "cowrie.src_ip", "source.ip"]
        else:
            country_fields = [es._get_field(index, "geo_country")]
            ip_fields = [es._get_field(index, "src_ip")]
        
        # Try each combination of country/IP fields until we get results
        got_results = False
        for country_field in country_fields:
            if got_results:
                break
            for ip_field in ip_fields:
                try:
                    result = await es.search(
                        index=index,
                        query=query,
                        size=0,
                        aggs={
                            "countries": {
                                "terms": {"field": country_field, "size": 300},
                                "aggs": {
                                    "unique_ips": {"cardinality": {"field": ip_field}}
                                }
                            }
                        }
                    )
                    
                    buckets = result.get("aggregations", {}).get("countries", {}).get("buckets", [])
                    if not buckets:
                        continue  # Try next field combination
                    
                    got_results = True
                    for bucket in buckets:
                        country = bucket["key"]
                        if not country or country in ["", "Unknown", "Private range"]:
                            continue
                            
                        if country not in country_data:
                            country_data[country] = {
                                "country": country,
                                "total_events": 0,
                                "unique_ips": 0,
                                "honeypots": {}
                            }
                        
                        country_data[country]["total_events"] += bucket["doc_count"]
                        country_data[country]["honeypots"][honeypot] = {
                            "events": bucket["doc_count"],
                            "ips": bucket["unique_ips"]["value"],
                            "color": HONEYPOT_COLORS.get(honeypot, "#ffffff")
                        }
                    break  # Success, exit ip_field loop
                except Exception as e:
                    # Try next field combination
                    continue
        
        if not got_results:
            print(f"Warning: No country data found for {honeypot} with any field combination")
    
    # Calculate unique IPs per country (deduplicated)
    for country in country_data.values():
        country["unique_ips"] = sum(hp["ips"] for hp in country["honeypots"].values())
    
    # Sort by events
    countries_list = sorted(country_data.values(), key=lambda x: -x["total_events"])
    
    return {
        "time_range": time_range,
        "countries": countries_list,
        "total_countries": len(countries_list),
        "total_unique_ips": global_stats["total_unique_ips"],
        "total_events": global_stats["total_events"]
    }


@router.get("/countries/{country_name}/attackers")
async def get_country_attackers(
    country_name: str,
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get detailed attacker information for a specific country."""
    es = get_es_service()
    
    attackers = {}
    
    for honeypot, index in HONEYPOT_INDICES.items():
        # Handle different field structures per honeypot
        # For Cowrie, try multiple country field options since geo data may be in different locations
        if honeypot == "cowrie":
            ip_fields = ["json.src_ip", "cowrie.src_ip", "source.ip"]
            country_fields = ["source.geo.country_name", "cowrie.geo.country_name"]
            city_fields = ["source.geo.city_name", "cowrie.geo.city_name"]
        elif honeypot == "dionaea":
            ip_fields = ["source.ip.keyword"]
            country_fields = ["source.geo.country_name.keyword"]
            city_fields = ["source.geo.city_name.keyword"]
        elif honeypot == "firewall":
            ip_fields = ["fw.src_ip"]
            country_fields = ["source.geo.country_name"]
            city_fields = ["source.geo.city_name"]
        else:
            ip_fields = ["source.ip"]
            country_fields = ["source.geo.country_name"]
            city_fields = ["source.geo.city_name"]
        
        # Apply firewall time offset
        is_firewall = honeypot == "firewall"
        time_query = es._get_time_range_query(time_range, is_firewall=is_firewall)
        
        # Try each combination of fields until we get results
        got_results = False
        for country_field in country_fields:
            if got_results:
                break
            for city_field in city_fields:
                if got_results:
                    break
                for ip_field in ip_fields:
                    try:
                        result = await es.search(
                            index=index,
                            query={
                                "bool": {
                                    "must": [
                                        time_query,
                                        {"term": {country_field: country_name}}
                                    ]
                                }
                            },
                            size=0,
                            aggs={
                                "attackers": {
                                    "terms": {"field": ip_field, "size": 100},
                                    "aggs": {
                                        "events": {"value_count": {"field": "@timestamp"}},
                                        "first_seen": {"min": {"field": "@timestamp"}},
                                        "last_seen": {"max": {"field": "@timestamp"}},
                                        "city": {
                                            "terms": {"field": city_field, "size": 1}
                                        }
                                    }
                                }
                            }
                        )
                        
                        buckets = result.get("aggregations", {}).get("attackers", {}).get("buckets", [])
                        if not buckets:
                            continue  # Try next field combination
                        
                        got_results = True
                        for bucket in buckets:
                            ip = bucket["key"]
                            if ip not in attackers:
                                city_buckets = bucket.get("city", {}).get("buckets", [])
                                city = city_buckets[0]["key"] if city_buckets else None
                                
                                attackers[ip] = {
                                    "ip": ip,
                                    "country": country_name,
                                    "city": city,
                                    "total_events": 0,
                                    "first_seen": bucket["first_seen"]["value_as_string"],
                                    "last_seen": bucket["last_seen"]["value_as_string"],
                                    "honeypots_attacked": [],
                                    "honeypot_details": {},
                                }
                            
                            attackers[ip]["total_events"] += bucket["doc_count"]
                            if honeypot not in attackers[ip]["honeypots_attacked"]:
                                attackers[ip]["honeypots_attacked"].append(honeypot)
                            if honeypot not in attackers[ip]["honeypot_details"]:
                                attackers[ip]["honeypot_details"][honeypot] = {"events": 0, "color": HONEYPOT_COLORS.get(honeypot, "#ffd700")}
                            attackers[ip]["honeypot_details"][honeypot]["events"] += bucket["doc_count"]
                            
                            # Update first/last seen
                            if bucket["first_seen"]["value_as_string"] < attackers[ip]["first_seen"]:
                                attackers[ip]["first_seen"] = bucket["first_seen"]["value_as_string"]
                            if bucket["last_seen"]["value_as_string"] > attackers[ip]["last_seen"]:
                                attackers[ip]["last_seen"] = bucket["last_seen"]["value_as_string"]
                        break  # Success, exit ip_field loop
                            
                    except Exception as e:
                        # Try next field combination
                        continue
    
    # Sort by total events
    sorted_attackers = sorted(attackers.values(), key=lambda x: -x["total_events"])
    
    return {
        "country": country_name,
        "time_range": time_range,
        "attackers": sorted_attackers,
        "total_attackers": len(sorted_attackers),
        "total_events": sum(a["total_events"] for a in sorted_attackers)
    }


@router.get("/top/list")
async def get_top_attackers_list(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(get_current_user)
):
    """Get top attackers across all honeypots (excludes firewall for consistency)."""
    es = get_es_service()
    
    attackers = {}
    
    # Exclude firewall to match Dashboard honeypot-only view
    honeypot_only_indices = {k: v for k, v in HONEYPOT_INDICES.items() if k != "firewall"}
    
    for honeypot, index in honeypot_only_indices.items():
        # Handle different field structures per honeypot
        # For Cowrie, try multiple country field options since geo data may be in different locations
        if honeypot == "cowrie":
            ip_fields = ["json.src_ip", "cowrie.src_ip", "source.ip"]
            country_fields = ["source.geo.country_name", "cowrie.geo.country_name"]
        elif honeypot == "dionaea":
            ip_fields = ["source.ip.keyword"]
            country_fields = ["source.geo.country_name.keyword"]
        else:
            ip_fields = ["source.ip"]
            country_fields = ["source.geo.country_name"]
        
        time_query = es._get_time_range_query(time_range, is_firewall=False)
        
        # Try each combination of fields until we get results
        got_results = False
        for country_field in country_fields:
            if got_results:
                break
            for ip_field in ip_fields:
                try:
                    result = await es.search(
                        index=index,
                        query=time_query,
                        size=0,
                        aggs={
                            "top_ips": {
                                "terms": {"field": ip_field, "size": limit * 2},
                                "aggs": {
                                    "events": {"value_count": {"field": "@timestamp"}},
                                    "country": {"terms": {"field": country_field, "size": 1}},
                                    "first_seen": {"min": {"field": "@timestamp"}},
                                    "last_seen": {"max": {"field": "@timestamp"}}
                                }
                            }
                        }
                    )
                    
                    buckets = result.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
                    if not buckets:
                        continue  # Try next field combination
                    
                    got_results = True
                    for bucket in buckets:
                        ip = bucket["key"]
                        country_buckets = bucket.get("country", {}).get("buckets", [])
                        country = country_buckets[0]["key"] if country_buckets else "Unknown"
                        
                        if ip not in attackers:
                            attackers[ip] = {
                                "ip": ip,
                                "country": country,
                                "total_events": 0,
                                "honeypots": [],
                                "first_seen": bucket["first_seen"]["value_as_string"],
                                "last_seen": bucket["last_seen"]["value_as_string"],
                            }
                        
                        attackers[ip]["total_events"] += bucket["doc_count"]
                        if honeypot not in attackers[ip]["honeypots"]:
                            attackers[ip]["honeypots"].append(honeypot)
                        
                        # Update first/last seen
                        if bucket["first_seen"]["value_as_string"] < attackers[ip]["first_seen"]:
                            attackers[ip]["first_seen"] = bucket["first_seen"]["value_as_string"]
                        if bucket["last_seen"]["value_as_string"] > attackers[ip]["last_seen"]:
                            attackers[ip]["last_seen"] = bucket["last_seen"]["value_as_string"]
                    break  # Success, exit ip_field loop
                            
                except Exception as e:
                    # Try next field combination
                    continue
    
    # Sort and limit
    total_unique_attackers = len(attackers)
    sorted_attackers = sorted(attackers.values(), key=lambda x: -x["total_events"])[:limit]
    
    return {
        "time_range": time_range,
        "attackers": sorted_attackers,
        "total": total_unique_attackers
    }
