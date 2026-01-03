"""Dionaea honeypot API routes."""

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
    DionaeaProtocolStats,
    DionaeaPortStats,
    DionaeaMalware,
)

router = APIRouter()
INDEX = "dionaea-*"


@router.get("/stats", response_model=StatsResponse)
async def get_dionaea_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Dionaea honeypot statistics."""
    es = get_es_service()
    
    total_events = await es.get_total_events(INDEX, time_range)
    unique_ips = await es.get_unique_ips(INDEX, time_range)
    
    return StatsResponse(
        total_events=total_events,
        unique_ips=unique_ips,
        time_range=time_range
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_dionaea_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Dionaea event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    timeline = await es.get_timeline(INDEX, time_range, interval)
    
    return TimelineResponse(
        data=[TimelinePoint(**point) for point in timeline],
        time_range=time_range
    )


@router.get("/geo", response_model=GeoDistributionResponse)
async def get_dionaea_geo(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get Dionaea geographic distribution."""
    es = get_es_service()
    
    geo_data = await es.get_geo_distribution(INDEX, time_range)
    
    return GeoDistributionResponse(
        data=[GeoPoint(**point) for point in geo_data],
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_dionaea_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top Dionaea attackers."""
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


@router.get("/protocols", response_model=List[DionaeaProtocolStats])
async def get_dionaea_protocols(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get protocol distribution for Dionaea."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "protocols": {
                "terms": {
                    "field": "network.transport.keyword",
                    "size": limit
                }
            }
        }
    )
    
    protocols = []
    for bucket in result.get("aggregations", {}).get("protocols", {}).get("buckets", []):
        protocols.append(DionaeaProtocolStats(
            protocol=bucket["key"],
            count=bucket["doc_count"]
        ))
    
    return protocols


@router.get("/ports", response_model=List[DionaeaPortStats])
async def get_dionaea_ports(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get port distribution for Dionaea."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"exists": {"field": "destination.port"}}
                ]
            }
        },
        size=0,
        aggs={
            "ports": {
                "terms": {
                    "field": "destination.port",
                    "size": limit
                },
                "aggs": {
                    "protocol": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["network.transport"]
                        }
                    }
                }
            }
        }
    )
    
    ports = []
    for bucket in result.get("aggregations", {}).get("ports", {}).get("buckets", []):
        hit = bucket["protocol"]["hits"]["hits"][0]["_source"] if bucket["protocol"]["hits"]["hits"] else {}
        
        ports.append(DionaeaPortStats(
            port=bucket["key"],
            count=bucket["doc_count"],
            protocol=hit.get("network", {}).get("transport")
        ))
    
    return ports


@router.get("/connections")
async def get_dionaea_connections(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get Dionaea connection events with details."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"exists": {"field": "source.ip"}},
                    {"term": {"dionaea.component": "connection"}}
                ]
            }
        },
        size=limit,
        sort=[{"@timestamp": "desc"}]
    )
    
    connections = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        
        connections.append({
            "id": hit["_id"],
            "timestamp": source.get("@timestamp"),
            "source_ip": source.get("source", {}).get("ip"),
            "source_port": source.get("source", {}).get("port"),
            "destination_ip": source.get("destination", {}).get("ip"),
            "destination_port": source.get("destination", {}).get("port"),
            "transport": source.get("network", {}).get("transport"),
            "message": source.get("dionaea", {}).get("msg"),
            "component": source.get("dionaea", {}).get("component"),
            "geo": {
                "country": source.get("source", {}).get("geo", {}).get("country_name"),
                "city": source.get("source", {}).get("geo", {}).get("city_name"),
            }
        })
    
    return {
        "total": result.get("hits", {}).get("total", {}).get("value", 0),
        "connections": connections
    }


@router.get("/malware", response_model=List[DionaeaMalware])
async def get_dionaea_malware(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get malware samples captured by Dionaea."""
    es = get_es_service()
    
    # Look for file download events
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range)
                ],
                "should": [
                    {"exists": {"field": "file.hash.md5"}},
                    {"exists": {"field": "file.hash.sha256"}},
                    {"match": {"dionaea.msg": "download"}}
                ],
                "minimum_should_match": 1
            }
        },
        size=limit,
        sort=[{"@timestamp": "desc"}]
    )
    
    malware_list = []
    seen_hashes = set()
    
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        file_info = source.get("file", {})
        hash_info = file_info.get("hash", {})
        md5 = hash_info.get("md5", "")
        
        if md5 and md5 not in seen_hashes:
            seen_hashes.add(md5)
            malware_list.append(DionaeaMalware(
                md5=md5,
                count=1,
                first_seen=source.get("@timestamp"),
                sha256=hash_info.get("sha256"),
                file_name=file_info.get("name")
            ))
    
    return malware_list


@router.get("/logs")
async def get_dionaea_logs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    component: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get Dionaea logs with filtering options."""
    es = get_es_service()
    
    filters = {}
    if component:
        filters["dionaea.component"] = component
    if src_ip:
        filters["source.ip"] = src_ip
    
    return await es.get_logs(INDEX, time_range, limit, search, filters)


@router.get("/heatmap")
async def get_dionaea_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly heatmap data for Dionaea."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    return {"data": heatmap_data, "time_range": time_range}


@router.get("/service-distribution")
async def get_dionaea_service_distribution(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get service attack distribution by port with service name mapping."""
    es = get_es_service()
    
    # Port to service name mapping
    port_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1723: "PPTP", 1900: "UPnP",
        3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 27017: "MongoDB"
    }
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"exists": {"field": "source.ip"}},
            {"term": {"dionaea.component.keyword": "connection"}}
        ]}},
        size=0,
        aggs={
            "by_port": {
                "terms": {"field": "destination.port", "size": 20},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip.keyword"}}
                }
            }
        }
    )
    
    services = []
    for bucket in result.get("aggregations", {}).get("by_port", {}).get("buckets", []):
        port = bucket["key"]
        services.append({
            "port": port,
            "service": port_services.get(port, f"Port {port}"),
            "count": bucket["doc_count"],
            "unique_ips": bucket.get("unique_ips", {}).get("value", 0)
        })
    
    return {"time_range": time_range, "services": services}


@router.get("/connection-states")
async def get_dionaea_connection_states(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get connection state distribution and lifecycle analysis."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_component": {
                "terms": {"field": "dionaea.component.keyword", "size": 20}
            },
            "avg_duration": {
                "filter": {"exists": {"field": "dionaea.duration"}},
                "aggs": {"value": {"avg": {"field": "dionaea.duration"}}}
            }
        }
    )
    
    components = []
    for bucket in result.get("aggregations", {}).get("by_component", {}).get("buckets", []):
        components.append({
            "component": bucket["key"],
            "count": bucket["doc_count"]
        })
    
    avg_duration = result.get("aggregations", {}).get("avg_duration", {}).get("value", {}).get("value")
    
    return {
        "time_range": time_range,
        "components": components,
        "avg_duration": round(avg_duration, 2) if avg_duration else None
    }


@router.get("/attack-sources")
async def get_dionaea_attack_sources(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get attack source diversity analysis - unique IPs per service."""
    es = get_es_service()
    
    port_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
        445: "SMB", 1433: "MSSQL", 3306: "MySQL", 5060: "SIP", 1900: "UPnP"
    }
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"exists": {"field": "source.ip"}},
            {"term": {"dionaea.component.keyword": "connection"}}
        ]}},
        size=0,
        aggs={
            "by_port": {
                "terms": {"field": "destination.port", "size": 15},
                "aggs": {
                    "unique_sources": {"cardinality": {"field": "source.ip.keyword"}},
                    "countries": {
                        "terms": {"field": "source.geo.country_name.keyword", "size": 5}
                    }
                }
            },
            "total_unique_ips": {"cardinality": {"field": "source.ip.keyword"}}
        }
    )
    
    attack_sources = []
    for bucket in result.get("aggregations", {}).get("by_port", {}).get("buckets", []):
        port = bucket["key"]
        countries = [c["key"] for c in bucket.get("countries", {}).get("buckets", [])]
        attack_sources.append({
            "port": port,
            "service": port_services.get(port, f"Port {port}"),
            "unique_ips": bucket.get("unique_sources", {}).get("value", 0),
            "total_connections": bucket["doc_count"],
            "top_countries": countries
        })
    
    return {
        "time_range": time_range,
        "attack_sources": attack_sources,
        "total_unique_ips": result.get("aggregations", {}).get("total_unique_ips", {}).get("value", 0)
    }


@router.get("/hourly-breakdown")
async def get_dionaea_hourly_breakdown(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly attack breakdown by service."""
    es = get_es_service()
    
    port_services = {
        21: "FTP", 80: "HTTP", 443: "HTTPS", 445: "SMB",
        1433: "MSSQL", 3306: "MySQL", 5060: "SIP", 1900: "UPnP"
    }
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"exists": {"field": "source.ip"}}
        ]}},
        size=0,
        aggs={
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h"
                },
                "aggs": {
                    "by_port": {
                        "terms": {"field": "destination.port", "size": 5}
                    }
                }
            }
        }
    )
    
    hourly_data = []
    for bucket in result.get("aggregations", {}).get("by_hour", {}).get("buckets", []):
        hour_data = {
            "timestamp": bucket["key_as_string"],
            "total": bucket["doc_count"]
        }
        for port_bucket in bucket.get("by_port", {}).get("buckets", []):
            port = port_bucket["key"]
            service = port_services.get(port, f"port_{port}")
            hour_data[service] = port_bucket["doc_count"]
        hourly_data.append(hour_data)
    
    return {"time_range": time_range, "hourly_data": hourly_data}


@router.get("/malware-analysis")
async def get_dionaea_malware_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get enhanced malware analysis - looking for download attempts, 
    HTTP paths, and potential payload indicators.
    """
    es = get_es_service()
    
    # Search for HTTP requests that look like malware downloads
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"dionaea.component.keyword": "http"}}
        ]}},
        size=500,
        sort=[{"@timestamp": "desc"}]
    )
    
    # Extract paths and URLs
    paths = {}
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        msg = source.get("dionaea", {}).get("msg", "")
        
        # Look for extracted paths
        if "Extracted path" in msg:
            path = msg.replace("Extracted path ", "").strip()
            if path not in paths:
                paths[path] = {"count": 0, "first_seen": source.get("@timestamp")}
            paths[path]["count"] += 1
    
    # Categorize paths
    categories = {
        "credential_files": [],
        "config_files": [],
        "shell_scripts": [],
        "executables": [],
        "web_exploits": [],
        "other": []
    }
    
    for path, data in sorted(paths.items(), key=lambda x: -x[1]["count"])[:100]:
        path_lower = path.lower()
        entry = {"path": path, "count": data["count"], "first_seen": data["first_seen"]}
        
        # Generate VirusTotal search link for suspicious paths
        if any(ext in path_lower for ext in [".exe", ".dll", ".bin", ".sh", ".pl", ".py"]):
            entry["suspicious"] = True
        
        if any(x in path_lower for x in [".env", "passwd", "credential", "password", "config", "wp-config"]):
            categories["credential_files"].append(entry)
        elif any(x in path_lower for x in [".conf", ".cfg", ".ini", ".xml", ".json"]):
            categories["config_files"].append(entry)
        elif any(x in path_lower for x in [".sh", ".bash", ".pl", ".py"]):
            categories["shell_scripts"].append(entry)
        elif any(x in path_lower for x in [".exe", ".dll", ".bin", ".elf"]):
            categories["executables"].append(entry)
        elif any(x in path_lower for x in ["phpunit", "cgi-bin", "eval", "admin", "wp-", "xmlrpc"]):
            categories["web_exploits"].append(entry)
        else:
            categories["other"].append(entry)
    
    # Get component breakdown
    component_result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_component": {
                "terms": {"field": "dionaea.component.keyword", "size": 20}
            }
        }
    )
    
    components = [
        {"component": b["key"], "count": b["doc_count"]}
        for b in component_result.get("aggregations", {}).get("by_component", {}).get("buckets", [])
    ]
    
    return {
        "time_range": time_range,
        "total_http_events": result.get("hits", {}).get("total", {}).get("value", 0),
        "unique_paths": len(paths),
        "categories": categories,
        "components": components,
        "summary": {
            "credential_attempts": len(categories["credential_files"]),
            "config_probes": len(categories["config_files"]),
            "shell_downloads": len(categories["shell_scripts"]),
            "executable_downloads": len(categories["executables"]),
            "web_exploits": len(categories["web_exploits"])
        }
    }


@router.get("/all-connections")
async def get_dionaea_all_connections(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    port: Optional[int] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get all Dionaea connections with pagination and filtering."""
    es = get_es_service()
    
    port_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1723: "PPTP", 1900: "UPnP",
        3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 27017: "MongoDB"
    }
    
    must_clauses = [
        es._get_time_range_query(time_range),
        {"exists": {"field": "source.ip"}}
    ]
    
    if port:
        must_clauses.append({"term": {"destination.port": port}})
    if src_ip:
        must_clauses.append({"term": {"source.ip": src_ip}})
    
    query = {"bool": {"must": must_clauses}}
    
    result = await es.search(
        index=INDEX,
        query=query,
        size=limit,
        from_=offset,
        sort=[{"@timestamp": "desc"}]
    )
    
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    
    connections = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        dionaea = source.get("dionaea", {})
        dest_port = source.get("destination", {}).get("port")
        
        connections.append({
            "id": hit["_id"],
            "timestamp": source.get("@timestamp"),
            "src_ip": source.get("source", {}).get("ip"),
            "src_port": source.get("source", {}).get("port"),
            "dst_ip": source.get("destination", {}).get("ip"),
            "dst_port": dest_port,
            "service": port_services.get(dest_port, f"Port {dest_port}") if dest_port else "Unknown",
            "transport": source.get("network", {}).get("transport"),
            "component": dionaea.get("component"),
            "message": dionaea.get("msg", "")[:200],
            "country": source.get("source", {}).get("geo", {}).get("country_name"),
            "city": source.get("source", {}).get("geo", {}).get("city_name"),
        })
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "connections": connections
    }
