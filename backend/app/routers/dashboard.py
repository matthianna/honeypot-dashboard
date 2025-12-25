"""Dashboard API routes."""

from typing import List
from fastapi import APIRouter, Depends, Query

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service
from app.models.schemas import (
    DashboardOverview,
    HoneypotStats,
    TopAttackersResponse,
    TopAttacker,
    TimelineResponse,
    TimelinePoint,
    GeoDistributionResponse,
    GeoPoint,
)

router = APIRouter()

# Internal IPs to exclude (post-query filtering for prefix ranges)
INTERNAL_IP_PREFIXES = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127."]
INTERNAL_IPS = {"193.246.121.231", "193.246.121.232", "193.246.121.233"}


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

# Honeypot colors for UI
HONEYPOT_COLORS = {
    "cowrie": "#39ff14",    # Neon green
    "dionaea": "#00d4ff",   # Neon blue
    "galah": "#ff6600",     # Neon orange
    "rdpy": "#bf00ff",      # Neon purple
    "heralding": "#ff3366", # Neon red
    "firewall": "#ffff00",  # Yellow
}


@router.get("/overview", response_model=DashboardOverview)
async def get_dashboard_overview(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get dashboard overview with stats for all honeypots.
    
    Returns aggregated statistics including total events and unique IPs
    for each honeypot in the specified time range.
    """
    es = get_es_service()
    honeypots: List[HoneypotStats] = []
    total_events = 0
    all_ips = set()
    
    for name, index in es.INDICES.items():
        events = await es.get_total_events(index, time_range)
        unique_ips = await es.get_unique_ips(index, time_range)
        
        honeypots.append(HoneypotStats(
            name=name,
            total_events=events,
            unique_ips=unique_ips,
            color=HONEYPOT_COLORS.get(name, "#ffffff")
        ))
        
        total_events += events
    
    # Get total unique IPs across all indices
    total_unique_ips = 0
    for _, index in es.INDICES.items():
        total_unique_ips += await es.get_unique_ips(index, time_range)
    
    return DashboardOverview(
        honeypots=honeypots,
        total_events=total_events,
        total_unique_ips=total_unique_ips,
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """
    Get top attackers across all honeypots.
    
    Aggregates attack data from all honeypots and returns the top
    attacking IPs sorted by event count. Excludes internal/private IPs.
    """
    es = get_es_service()
    ip_counts = {}
    ip_geo = {}
    
    for _, index in es.INDICES.items():
        top_ips = await es.get_top_source_ips(index, time_range, size=100)
        
        for ip_data in top_ips:
            ip = ip_data["ip"]
            
            # Skip internal/private IPs
            if is_internal_ip(ip):
                continue
                
            count = ip_data["count"]
            geo = ip_data.get("geo", {})
            
            if ip in ip_counts:
                ip_counts[ip] += count
            else:
                ip_counts[ip] = count
                ip_geo[ip] = geo
    
    # Sort by count and take top N
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    attackers = [
        TopAttacker(
            ip=ip,
            count=count,
            country=ip_geo.get(ip, {}).get("country_name"),
            city=ip_geo.get(ip, {}).get("city_name")
        )
        for ip, count in sorted_ips
    ]
    
    return TopAttackersResponse(data=attackers, time_range=time_range)


@router.get("/timeline", response_model=TimelineResponse)
async def get_dashboard_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get aggregated timeline across all honeypots.
    
    Returns event counts over time, suitable for charting.
    """
    es = get_es_service()
    
    # Determine interval based on time range
    intervals = {
        "1h": "5m",
        "24h": "1h",
        "7d": "6h",
        "30d": "1d",
    }
    interval = intervals.get(time_range, "1h")
    
    # Aggregate timeline data from all indices
    timeline_data = {}
    
    for _, index in es.INDICES.items():
        timeline = await es.get_timeline(index, time_range, interval)
        
        for point in timeline:
            ts = point["timestamp"]
            if ts in timeline_data:
                timeline_data[ts] += point["count"]
            else:
                timeline_data[ts] = point["count"]
    
    # Sort by timestamp
    sorted_data = sorted(timeline_data.items(), key=lambda x: x[0])
    
    data = [
        TimelinePoint(timestamp=ts, count=count)
        for ts, count in sorted_data
    ]
    
    return TimelineResponse(data=data, time_range=time_range)


@router.get("/geo-stats", response_model=GeoDistributionResponse)
async def get_geo_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get geographic distribution of attacks across all honeypots.
    
    Returns attack counts by country.
    """
    es = get_es_service()
    country_counts = {}
    
    for _, index in es.INDICES.items():
        geo_data = await es.get_geo_distribution(index, time_range)
        
        for point in geo_data:
            country = point["country"]
            count = point["count"]
            
            if country in country_counts:
                country_counts[country] += count
            else:
                country_counts[country] = count
    
    # Sort by count
    sorted_data = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    
    data = [
        GeoPoint(country=country, count=count)
        for country, count in sorted_data
    ]
    
    return GeoDistributionResponse(data=data, time_range=time_range)


@router.get("/protocol-distribution")
async def get_protocol_distribution(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get protocol distribution across all honeypots.
    Shows breakdown of SSH, Telnet, HTTP, RDP, etc.
    """
    es = get_es_service()
    protocol_counts = {}
    
    # Cowrie = SSH/Telnet
    cowrie_events = await es.get_total_events(es.INDICES["cowrie"], time_range)
    if cowrie_events > 0:
        protocol_counts["SSH/Telnet"] = cowrie_events
    
    # Dionaea - get by port
    try:
        result = await es.search(
            index=es.INDICES["dionaea"],
            query={"bool": {"must": [
                es._get_time_range_query(time_range),
                {"exists": {"field": "source.ip"}}
            ]}},
            size=0,
            aggs={"by_port": {"terms": {"field": "destination.port", "size": 10}}}
        )
        port_names = {
            21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 
            1433: "MSSQL", 3306: "MySQL", 5060: "SIP", 1900: "UPnP"
        }
        for bucket in result.get("aggregations", {}).get("by_port", {}).get("buckets", []):
            port = bucket["key"]
            name = port_names.get(port, f"Port {port}")
            protocol_counts[name] = protocol_counts.get(name, 0) + bucket["doc_count"]
    except Exception:
        pass
    
    # Galah = HTTP
    galah_events = await es.get_total_events(es.INDICES["galah"], time_range)
    if galah_events > 0:
        protocol_counts["HTTP (Galah)"] = galah_events
    
    # RDPY = RDP
    rdpy_events = await es.get_total_events(es.INDICES["rdpy"], time_range)
    if rdpy_events > 0:
        protocol_counts["RDP"] = rdpy_events
    
    # Heralding - get by protocol
    try:
        result = await es.search(
            index=es.INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"by_protocol": {"terms": {"field": "network.protocol.keyword", "size": 10}}}
        )
        for bucket in result.get("aggregations", {}).get("by_protocol", {}).get("buckets", []):
            proto = bucket["key"].upper()
            protocol_counts[proto] = protocol_counts.get(proto, 0) + bucket["doc_count"]
    except Exception:
        pass
    
    # Convert to list sorted by count
    protocols = [
        {"protocol": name, "count": count}
        for name, count in sorted(protocol_counts.items(), key=lambda x: -x[1])
    ]
    
    return {"time_range": time_range, "protocols": protocols}


@router.get("/hourly-heatmap")
async def get_hourly_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get hourly attack heatmap data (hour of day x day of week).
    """
    es = get_es_service()
    
    # Initialize 7x24 matrix (day x hour)
    heatmap = [[0 for _ in range(24)] for _ in range(7)]
    
    for _, index in es.INDICES.items():
        try:
            data = await es.get_hourly_heatmap(index, time_range)
            for point in data:
                day = point["day"]  # 0-6
                hour = point["hour"]  # 0-23
                count = point["count"]
                if 0 <= day < 7 and 0 <= hour < 24:
                    heatmap[day][hour] += count
        except Exception:
            pass
    
    # Convert to flat list for frontend
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    result = []
    for day_idx, day_name in enumerate(days):
        for hour in range(24):
            result.append({
                "day": day_name,
                "day_index": day_idx,
                "hour": hour,
                "count": heatmap[day_idx][hour]
            })
    
    return {"time_range": time_range, "heatmap": result}


@router.get("/attack-velocity")
async def get_attack_velocity(
    _: str = Depends(get_current_user)
):
    """
    Get attack velocity - events per minute for the last hour.
    """
    es = get_es_service()
    
    minute_counts = {}
    
    for _, index in es.INDICES.items():
        try:
            result = await es.search(
                index=index,
                query=es._get_time_range_query("1h"),
                size=0,
                aggs={
                    "by_minute": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1m"
                        }
                    }
                }
            )
            for bucket in result.get("aggregations", {}).get("by_minute", {}).get("buckets", []):
                ts = bucket["key_as_string"]
                count = bucket["doc_count"]
                minute_counts[ts] = minute_counts.get(ts, 0) + count
        except Exception:
            pass
    
    # Convert to sorted list
    velocity = [
        {"timestamp": ts, "count": count}
        for ts, count in sorted(minute_counts.items())
    ]
    
    # Calculate stats
    counts = list(minute_counts.values()) if minute_counts else [0]
    avg_rate = sum(counts) / len(counts) if counts else 0
    max_rate = max(counts) if counts else 0
    current_rate = counts[-1] if counts else 0
    
    return {
        "velocity": velocity[-60:],  # Last 60 minutes
        "stats": {
            "avg_per_minute": round(avg_rate, 1),
            "max_per_minute": max_rate,
            "current_per_minute": current_rate
        }
    }


@router.get("/threat-summary")
async def get_threat_summary(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get threat severity breakdown categorized by type.
    """
    es = get_es_service()
    
    summary = {
        "login_attempts": 0,
        "command_execution": 0,
        "port_scans": 0,
        "web_attacks": 0,
        "credential_harvesting": 0,
    }
    
    # Cowrie: login attempts and commands
    try:
        result = await es.search(
            index=es.INDICES["cowrie"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "by_event": {"terms": {"field": "cowrie.eventid.keyword", "size": 20}}
            }
        )
        for bucket in result.get("aggregations", {}).get("by_event", {}).get("buckets", []):
            event = bucket["key"]
            count = bucket["doc_count"]
            if "login" in event:
                summary["login_attempts"] += count
            elif "command" in event or "input" in event:
                summary["command_execution"] += count
    except Exception:
        pass
    
    # Heralding: credential attempts
    try:
        result = await es.search(
            index=es.INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"total_attempts": {"sum": {"field": "num_auth_attempts"}}}
        )
        summary["credential_harvesting"] = int(result.get("aggregations", {}).get("total_attempts", {}).get("value", 0))
    except Exception:
        pass
    
    # Galah: web attacks
    summary["web_attacks"] = await es.get_total_events(es.INDICES["galah"], time_range)
    
    # Firewall: port scans (estimate from unique port counts)
    try:
        result = await es.search(
            index=es.INDICES["firewall"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"unique_ports": {"cardinality": {"field": "destination.port"}}}
        )
        # Rough estimate: if source IP hits many ports, it's scanning
        summary["port_scans"] = result.get("aggregations", {}).get("unique_ports", {}).get("value", 0)
    except Exception:
        pass
    
    return {"time_range": time_range, "summary": summary}


@router.get("/mitre-coverage")
async def get_mitre_coverage(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get MITRE ATT&CK technique coverage based on honeypot detections.
    """
    from app.services.mitre import MITRE_TECHNIQUES, TACTICS_ORDER, get_honeypot_technique_mapping
    
    es = get_es_service()
    technique_counts = {}
    honeypot_mapping = get_honeypot_technique_mapping()
    
    # Count events that map to each technique
    
    # Cowrie: Brute Force (T1110), Valid Accounts (T1078), Unix Shell (T1059.004)
    try:
        result = await es.search(
            index=es.INDICES["cowrie"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "by_event": {"terms": {"field": "cowrie.eventid.keyword", "size": 50}}
            }
        )
        for bucket in result.get("aggregations", {}).get("by_event", {}).get("buckets", []):
            event = bucket["key"]
            count = bucket["doc_count"]
            if "login.failed" in event:
                technique_counts["T1110.001"] = technique_counts.get("T1110.001", 0) + count
                technique_counts["T1110"] = technique_counts.get("T1110", 0) + count
            elif "login.success" in event:
                technique_counts["T1078"] = technique_counts.get("T1078", 0) + count
            elif "command" in event or "input" in event:
                technique_counts["T1059.004"] = technique_counts.get("T1059.004", 0) + count
                technique_counts["T1059"] = technique_counts.get("T1059", 0) + count
            elif "session.connect" in event:
                technique_counts["T1021.004"] = technique_counts.get("T1021.004", 0) + count
    except Exception:
        pass
    
    # Heralding: Brute Force (T1110), External Remote Services (T1133)
    try:
        result = await es.search(
            index=es.INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "total_attempts": {"sum": {"field": "num_auth_attempts"}},
                "total_sessions": {"value_count": {"field": "@timestamp"}}
            }
        )
        auth_attempts = int(result.get("aggregations", {}).get("total_attempts", {}).get("value", 0))
        sessions = result.get("aggregations", {}).get("total_sessions", {}).get("value", 0)
        if auth_attempts > 0:
            technique_counts["T1110"] = technique_counts.get("T1110", 0) + auth_attempts
            technique_counts["T1110.001"] = technique_counts.get("T1110.001", 0) + auth_attempts
        if sessions > 0:
            technique_counts["T1133"] = technique_counts.get("T1133", 0) + sessions
    except Exception:
        pass
    
    # Galah: Exploit Public-Facing App (T1190), Active Scanning (T1595)
    try:
        galah_events = await es.get_total_events(es.INDICES["galah"], time_range)
        if galah_events > 0:
            technique_counts["T1190"] = technique_counts.get("T1190", 0) + galah_events
            technique_counts["T1595"] = technique_counts.get("T1595", 0) + galah_events
            technique_counts["T1595.002"] = technique_counts.get("T1595.002", 0) + galah_events
    except Exception:
        pass
    
    # Dionaea: Exploit Public-Facing App (T1190), Non-Standard Port (T1571)
    try:
        dionaea_events = await es.get_total_events(es.INDICES["dionaea"], time_range)
        if dionaea_events > 0:
            technique_counts["T1190"] = technique_counts.get("T1190", 0) + dionaea_events
            technique_counts["T1571"] = technique_counts.get("T1571", 0) + dionaea_events
    except Exception:
        pass
    
    # RDPY: RDP (T1021.001), Brute Force (T1110)
    try:
        rdpy_events = await es.get_total_events(es.INDICES["rdpy"], time_range)
        if rdpy_events > 0:
            technique_counts["T1021.001"] = technique_counts.get("T1021.001", 0) + rdpy_events
            technique_counts["T1021"] = technique_counts.get("T1021", 0) + rdpy_events
    except Exception:
        pass
    
    # Firewall: Network Service Discovery (T1046), Active Scanning (T1595)
    try:
        result = await es.search(
            index=es.INDICES["firewall"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "scanners": {
                    "terms": {"field": "source.ip", "size": 1000},
                    "aggs": {
                        "unique_ports": {"cardinality": {"field": "destination.port"}}
                    }
                }
            }
        )
        port_scan_count = 0
        for bucket in result.get("aggregations", {}).get("scanners", {}).get("buckets", []):
            unique_ports = bucket.get("unique_ports", {}).get("value", 0)
            if unique_ports >= 5:  # Scanning if hitting 5+ ports
                port_scan_count += bucket["doc_count"]
        if port_scan_count > 0:
            technique_counts["T1046"] = technique_counts.get("T1046", 0) + port_scan_count
            technique_counts["T1595"] = technique_counts.get("T1595", 0) + port_scan_count
    except Exception:
        pass
    
    # Build response with technique details
    techniques_with_counts = []
    for tech_id, tech_info in MITRE_TECHNIQUES.items():
        count = technique_counts.get(tech_id, 0)
        techniques_with_counts.append({
            "id": tech_id,
            "name": tech_info["name"],
            "tactic": tech_info["tactic"],
            "description": tech_info["description"],
            "count": count,
            "detected": count > 0,
        })
    
    # Group by tactic
    tactics = {}
    for tech in techniques_with_counts:
        tactic = tech["tactic"]
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(tech)
    
    # Order tactics
    ordered_tactics = []
    for tactic_name in TACTICS_ORDER:
        if tactic_name in tactics:
            ordered_tactics.append({
                "tactic": tactic_name,
                "techniques": sorted(tactics[tactic_name], key=lambda x: -x["count"])
            })
    
    # Summary stats
    total_techniques = len([t for t in techniques_with_counts if t["detected"]])
    total_events = sum(technique_counts.values())
    
    return {
        "time_range": time_range,
        "tactics": ordered_tactics,
        "summary": {
            "techniques_detected": total_techniques,
            "total_technique_events": total_events,
            "top_techniques": sorted(techniques_with_counts, key=lambda x: -x["count"])[:5]
        }
    }


@router.get("/threat-intel")
async def get_threat_intel(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get threat intelligence - IPs attacking multiple honeypots.
    """
    es = get_es_service()
    
    # Get IPs from each honeypot
    honeypot_ips = {}
    
    # Cowrie
    try:
        result = await es.search(
            index=es.INDICES["cowrie"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"ips": {"terms": {"field": "cowrie.src_ip.keyword", "size": 500}}}
        )
        honeypot_ips["cowrie"] = {b["key"]: b["doc_count"] for b in result.get("aggregations", {}).get("ips", {}).get("buckets", [])}
    except Exception:
        honeypot_ips["cowrie"] = {}
    
    # Galah
    try:
        result = await es.search(
            index=es.INDICES["galah"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"ips": {"terms": {"field": "source.ip", "size": 500}}}
        )
        honeypot_ips["galah"] = {b["key"]: b["doc_count"] for b in result.get("aggregations", {}).get("ips", {}).get("buckets", [])}
    except Exception:
        honeypot_ips["galah"] = {}
    
    # Dionaea
    try:
        result = await es.search(
            index=es.INDICES["dionaea"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"ips": {"terms": {"field": "source.ip.keyword", "size": 500}}}
        )
        honeypot_ips["dionaea"] = {b["key"]: b["doc_count"] for b in result.get("aggregations", {}).get("ips", {}).get("buckets", [])}
    except Exception:
        honeypot_ips["dionaea"] = {}
    
    # Heralding
    try:
        result = await es.search(
            index=es.INDICES["heralding"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"ips": {"terms": {"field": "source.ip", "size": 500}}}
        )
        honeypot_ips["heralding"] = {b["key"]: b["doc_count"] for b in result.get("aggregations", {}).get("ips", {}).get("buckets", [])}
    except Exception:
        honeypot_ips["heralding"] = {}
    
    # RDPY
    try:
        result = await es.search(
            index=es.INDICES["rdpy"],
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={"ips": {"terms": {"field": "source.ip", "size": 500}}}
        )
        honeypot_ips["rdpy"] = {b["key"]: b["doc_count"] for b in result.get("aggregations", {}).get("ips", {}).get("buckets", [])}
    except Exception:
        honeypot_ips["rdpy"] = {}
    
    # Find IPs that hit multiple honeypots
    all_ips = set()
    for hp_data in honeypot_ips.values():
        all_ips.update(hp_data.keys())
    
    cross_honeypot_actors = []
    for ip in all_ips:
        if is_internal_ip(ip):
            continue
        
        honeypots_hit = []
        total_events = 0
        for hp_name, hp_data in honeypot_ips.items():
            if ip in hp_data:
                honeypots_hit.append(hp_name)
                total_events += hp_data[ip]
        
        if len(honeypots_hit) >= 2:  # Only IPs hitting 2+ honeypots
            cross_honeypot_actors.append({
                "ip": ip,
                "honeypots": honeypots_hit,
                "honeypot_count": len(honeypots_hit),
                "total_events": total_events,
            })
    
    # Sort by number of honeypots hit, then by total events
    cross_honeypot_actors.sort(key=lambda x: (-x["honeypot_count"], -x["total_events"]))
    
    # Calculate summary stats
    total_unique_ips = len([ip for ip in all_ips if not is_internal_ip(ip)])
    multi_honeypot_ips = len(cross_honeypot_actors)
    
    return {
        "time_range": time_range,
        "cross_honeypot_actors": cross_honeypot_actors[:30],
        "summary": {
            "total_unique_attackers": total_unique_ips,
            "multi_honeypot_attackers": multi_honeypot_ips,
            "multi_percentage": round(multi_honeypot_ips / total_unique_ips * 100, 1) if total_unique_ips > 0 else 0,
        },
        "honeypot_stats": {hp: len(data) for hp, data in honeypot_ips.items()}
    }


@router.get("/top-threat-actors")
async def get_top_threat_actors(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get top threat actors ranked by overall activity and diversity.
    """
    es = get_es_service()
    
    # Combine data from all honeypots to rank threat actors
    ip_scores = {}
    
    # Get data from each honeypot
    honeypots = ["cowrie", "galah", "dionaea", "heralding", "rdpy"]
    ip_fields = {
        "cowrie": "cowrie.src_ip.keyword",
        "galah": "source.ip",
        "dionaea": "source.ip.keyword",
        "heralding": "source.ip",
        "rdpy": "source.ip",
    }
    
    for hp in honeypots:
        try:
            result = await es.search(
                index=es.INDICES.get(hp, f".ds-{hp}-*"),
                query=es._get_time_range_query(time_range),
                size=0,
                aggs={"ips": {"terms": {"field": ip_fields[hp], "size": 200}}}
            )
            for bucket in result.get("aggregations", {}).get("ips", {}).get("buckets", []):
                ip = bucket["key"]
                if is_internal_ip(ip):
                    continue
                if ip not in ip_scores:
                    ip_scores[ip] = {"ip": ip, "honeypots": set(), "total_events": 0, "honeypot_details": {}}
                ip_scores[ip]["honeypots"].add(hp)
                ip_scores[ip]["total_events"] += bucket["doc_count"]
                ip_scores[ip]["honeypot_details"][hp] = bucket["doc_count"]
        except Exception:
            pass
    
    # Calculate threat score (weighted by diversity and volume)
    threat_actors = []
    for ip, data in ip_scores.items():
        diversity_score = len(data["honeypots"]) * 100
        volume_score = min(data["total_events"], 1000)  # Cap at 1000
        threat_score = diversity_score + volume_score
        
        threat_actors.append({
            "ip": ip,
            "honeypots": list(data["honeypots"]),
            "honeypot_count": len(data["honeypots"]),
            "total_events": data["total_events"],
            "threat_score": threat_score,
            "details": data["honeypot_details"],
        })
    
    # Sort by threat score
    threat_actors.sort(key=lambda x: -x["threat_score"])
    
    return {
        "time_range": time_range,
        "threat_actors": threat_actors[:20],
        "total_actors": len(threat_actors)
    }

