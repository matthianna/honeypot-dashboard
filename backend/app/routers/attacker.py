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
    if honeypot == "cowrie":
        return event.get("cowrie", {}).get("geo", {}).get("country_name")
    else:
        return event.get("source", {}).get("geo", {}).get("country_name")


def extract_src_ip_from_event(event: dict, honeypot: str) -> Optional[str]:
    """Extract source IP from event based on honeypot type."""
    if honeypot == "cowrie":
        return event.get("cowrie", {}).get("src_ip")
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
    
    # Get events for this IP across all honeypots
    events_by_honeypot = await es.get_events_for_ip(ip, time_range=time_range)
    
    if not events_by_honeypot:
        raise HTTPException(status_code=404, detail=f"No events found for IP {ip}")
    
    # Aggregate data
    total_events = 0
    all_timestamps = []
    countries = set()
    honeypot_activity = []
    credentials_tried = []
    commands_executed = []
    
    for honeypot, events in events_by_honeypot.items():
        total_events += len(events)
        
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
            
            # Extract credentials based on honeypot type
            if honeypot == "cowrie":
                cowrie = event.get("cowrie", {})
                username = cowrie.get("username")
                password = cowrie.get("password")
                if username:
                    credentials_tried.append({
                        "username": username,
                        "password": password or ""
                    })
                
                # Extract commands
                if cowrie.get("eventid") == "cowrie.command.input":
                    command = cowrie.get("input")
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
        
        if timestamps:
            timestamps.sort()
            honeypot_activity.append(HoneypotActivity(
                honeypot=honeypot,
                event_count=len(events),
                first_seen=timestamps[0],
                last_seen=timestamps[-1]
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
    
    return AttackerProfile(
        ip=ip,
        total_events=total_events,
        first_seen=all_timestamps[0] if all_timestamps else "",
        last_seen=all_timestamps[-1] if all_timestamps else "",
        countries=list(countries),
        honeypot_activity=honeypot_activity,
        credentials_tried=unique_credentials if unique_credentials else None,
        commands_executed=unique_commands if unique_commands else None
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
}

HONEYPOT_COLORS = {
    "cowrie": "#39ff14",
    "dionaea": "#00d4ff",
    "galah": "#ff6600",
    "rdpy": "#bf00ff",
    "heralding": "#ff3366",
}


@router.get("/countries/list")
async def get_attackers_by_country(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get attacker statistics grouped by country."""
    es = get_es_service()
    
    countries = {}
    
    for honeypot, index in HONEYPOT_INDICES.items():
        try:
            # Determine fields based on honeypot
            if honeypot == "cowrie":
                ip_field = "cowrie.src_ip"
                country_field = "cowrie.geo.country_name"
            else:
                ip_field = "source.ip"
                country_field = "source.geo.country_name.keyword"
            
            result = await es.search(
                index=index,
                query=es._get_time_range_query(time_range),
                size=0,
                aggs={
                    "countries": {
                        "terms": {"field": country_field, "size": 100},
                        "aggs": {
                            "unique_ips": {"cardinality": {"field": ip_field}},
                            "events": {"value_count": {"field": "@timestamp"}}
                        }
                    }
                }
            )
            
            for bucket in result.get("aggregations", {}).get("countries", {}).get("buckets", []):
                country = bucket["key"]
                if country not in countries:
                    countries[country] = {
                        "country": country,
                        "total_events": 0,
                        "unique_ips": 0,
                        "honeypots": {},
                    }
                
                countries[country]["total_events"] += bucket["doc_count"]
                countries[country]["unique_ips"] += bucket["unique_ips"]["value"]
                countries[country]["honeypots"][honeypot] = {
                    "events": bucket["doc_count"],
                    "ips": bucket["unique_ips"]["value"],
                    "color": HONEYPOT_COLORS[honeypot]
                }
        except Exception as e:
            print(f"Error fetching {honeypot}: {e}")
            continue
    
    # Sort by total events
    sorted_countries = sorted(countries.values(), key=lambda x: -x["total_events"])
    
    return {
        "time_range": time_range,
        "countries": sorted_countries,
        "total_countries": len(sorted_countries)
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
        try:
            # Determine fields based on honeypot
            if honeypot == "cowrie":
                ip_field = "cowrie.src_ip"
                country_field = "cowrie.geo.country_name"
                city_field = "cowrie.geo.city_name"
            else:
                ip_field = "source.ip"
                country_field = "source.geo.country_name.keyword"
                city_field = "source.geo.city_name.keyword"
            
            result = await es.search(
                index=index,
                query={
                    "bool": {
                        "must": [
                            es._get_time_range_query(time_range),
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
            
            for bucket in result.get("aggregations", {}).get("attackers", {}).get("buckets", []):
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
                attackers[ip]["honeypots_attacked"].append(honeypot)
                attackers[ip]["honeypot_details"][honeypot] = {
                    "events": bucket["doc_count"],
                    "color": HONEYPOT_COLORS[honeypot]
                }
                
                # Update first/last seen
                if bucket["first_seen"]["value_as_string"] < attackers[ip]["first_seen"]:
                    attackers[ip]["first_seen"] = bucket["first_seen"]["value_as_string"]
                if bucket["last_seen"]["value_as_string"] > attackers[ip]["last_seen"]:
                    attackers[ip]["last_seen"] = bucket["last_seen"]["value_as_string"]
                    
        except Exception as e:
            print(f"Error fetching {honeypot} for {country_name}: {e}")
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
    """Get top attackers across all honeypots."""
    es = get_es_service()
    
    attackers = {}
    
    for honeypot, index in HONEYPOT_INDICES.items():
        try:
            if honeypot == "cowrie":
                ip_field = "cowrie.src_ip"
                country_field = "cowrie.geo.country_name"
            else:
                ip_field = "source.ip"
                country_field = "source.geo.country_name.keyword"
            
            result = await es.search(
                index=index,
                query=es._get_time_range_query(time_range),
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
            
            for bucket in result.get("aggregations", {}).get("top_ips", {}).get("buckets", []):
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
                attackers[ip]["honeypots"].append(honeypot)
                
                # Update first/last seen
                if bucket["first_seen"]["value_as_string"] < attackers[ip]["first_seen"]:
                    attackers[ip]["first_seen"] = bucket["first_seen"]["value_as_string"]
                if bucket["last_seen"]["value_as_string"] > attackers[ip]["last_seen"]:
                    attackers[ip]["last_seen"] = bucket["last_seen"]["value_as_string"]
                    
        except Exception as e:
            print(f"Error fetching {honeypot}: {e}")
            continue
    
    # Sort and limit
    sorted_attackers = sorted(attackers.values(), key=lambda x: -x["total_events"])[:limit]
    
    return {
        "time_range": time_range,
        "attackers": sorted_attackers,
        "total": len(sorted_attackers)
    }
