"""Elasticsearch service for querying honeypot data."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import structlog
from elasticsearch import AsyncElasticsearch

logger = structlog.get_logger()

# Internal/private IPs to exclude from statistics
INTERNAL_IPS = {"193.246.121.231", "193.246.121.232", "193.246.121.233"}
INTERNAL_IP_PREFIXES = [
    "192.168.", "10.", "127.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", 
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", 
    "172.28.", "172.29.", "172.30.", "172.31."
]


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


class ElasticsearchService:
    """Service for interacting with Elasticsearch."""
    
    # Index patterns for each honeypot (updated based on actual ES indices)
    INDICES = {
        "cowrie": ".ds-cowrie-*",
        "dionaea": "dionaea-*",
        "galah": ".ds-galah-*",
        "rdpy": ".ds-rdpy-*",
        "heralding": ".ds-heralding-*",
        "firewall": ".ds-filebeat-*",
    }
    
    # Field mappings for each honeypot (src_ip and geo fields vary by index)
    # NOTE: Cowrie now uses json.* structure from new filebeat pipeline
    FIELD_MAPPINGS = {
        "cowrie": {
            "src_ip": "json.src_ip",  # Updated: now in json.* namespace
            "geo_country": "source.geo.country_name",  # GeoIP enrichment in source.*
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "session": "json.session",  # Updated
            "eventid": "json.eventid",  # Updated
            "sensor": "observer.name",  # Updated: sensor name in observer.name
        },
        "dionaea": {
            # Note: Dionaea uses regular indices with text+keyword multi-fields
            "src_ip": "source.ip.keyword",  # Text field needs .keyword for aggregations
            "geo_country": "source.geo.country_name.keyword",
            "geo_city": "source.geo.city_name.keyword",
            "geo_location": "source.geo.location",
            "component": "dionaea.component",
            "transport": "network.transport",
            "dst_port": "destination.port",
        },
        "galah": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "session": "session.id",
            "http_method": "http.request.method",
            "http_uri": "url.path",
        },
        "rdpy": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
        },
        "heralding": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "session": "session_id",
            "protocol": "network.protocol",  # Already keyword type
            "dst_port": "destination.port",
        },
        "firewall": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type in filebeat index
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "action": "fw.action",  # Already keyword type
            "dst_port": "destination.port",
            "dst_ip": "destination.ip",
            "transport": "network.transport",  # Already keyword type
            "direction": "network.direction",  # Already keyword type
        },
    }
    
    def __init__(self, elasticsearch_url: str):
        """Initialize Elasticsearch service."""
        self.url = elasticsearch_url
        self.client: Optional[AsyncElasticsearch] = None
    
    async def connect(self):
        """Connect to Elasticsearch."""
        self.client = AsyncElasticsearch(
            hosts=[self.url],
            verify_certs=False,
            request_timeout=30,
        )
        
        # Verify connection (don't fail if Elasticsearch is not available)
        try:
            info = await self.client.info()
            logger.info("elasticsearch_connected", version=info["version"]["number"])
        except Exception as e:
            logger.warning("elasticsearch_connection_failed", error=str(e), url=self.url)
            logger.warning("elasticsearch_will_retry", message="Will retry on each request")
    
    async def close(self):
        """Close Elasticsearch connection."""
        if self.client:
            await self.client.close()
    
    def _get_honeypot_from_index(self, index: str) -> str:
        """Determine honeypot type from index pattern."""
        for honeypot, pattern in self.INDICES.items():
            if pattern == index or honeypot in index.lower():
                return honeypot
        return "firewall"  # Default fallback
    
    def _get_field(self, index: str, field_type: str) -> str:
        """Get the correct field name for a honeypot index."""
        honeypot = self._get_honeypot_from_index(index)
        mapping = self.FIELD_MAPPINGS.get(honeypot, self.FIELD_MAPPINGS["firewall"])
        return mapping.get(field_type, field_type)
    
    def _get_time_range_query(self, time_range: str = "24h") -> Dict[str, Any]:
        """Get time range filter for queries."""
        now = datetime.utcnow()
        
        time_ranges = {
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }
        
        delta = time_ranges.get(time_range, timedelta(hours=24))
        start_time = now - delta
        
        return {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": now.isoformat(),
                }
            }
        }
    
    def _get_base_filter(self, index: str) -> List[Dict[str, Any]]:
        """Get base filters for each honeypot to exclude noise.
        
        For Dionaea: Only include events with source.ip (real connections, not debug logs)
        """
        honeypot = self._get_honeypot_from_index(index)
        
        if honeypot == "dionaea":
            # Only include actual connection events (those with source.ip)
            return [{"exists": {"field": "source.ip"}}]
        
        return []
    
    def _get_internal_ip_exclusion(self, index: str) -> List[Dict[str, Any]]:
        """Get must_not clauses to exclude internal IPs.
        
        Uses 'terms' query for specific IPs only.
        For the 192.168.211.* range, data is filtered post-query if needed.
        """
        src_ip_field = self._get_field(index, "src_ip")
        
        # Combine all internal IPs into a single terms query
        # This is the safest approach that works for both text and ip field types
        all_internal = list(INTERNAL_IPS)
        
        return [{"terms": {src_ip_field: all_internal}}]
    
    async def get_total_events(self, index: str, time_range: str = "24h", exclude_internal: bool = True) -> int:
        """Get total event count for an index, excluding internal IPs and noise."""
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if exclude_internal:
                query["bool"]["must_not"] = self._get_internal_ip_exclusion(index)
            
            result = await self.client.count(
                index=index,
                body={"query": query}
            )
            return result["count"]
        except Exception as e:
            logger.error("elasticsearch_count_failed", index=index, error=str(e))
            return 0
    
    async def get_unique_ips(self, index: str, time_range: str = "24h", exclude_internal: bool = True) -> int:
        """Get unique source IP count for an index, excluding internal IPs and noise."""
        src_ip_field = self._get_field(index, "src_ip")
        
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if exclude_internal:
                query["bool"]["must_not"] = self._get_internal_ip_exclusion(index)
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": {
                        "unique_ips": {
                            "cardinality": {
                                "field": src_ip_field
                            }
                        }
                    }
                }
            )
            return result["aggregations"]["unique_ips"]["value"]
        except Exception as e:
            logger.error("elasticsearch_unique_ips_failed", index=index, error=str(e))
            return 0
    
    async def get_timeline(
        self,
        index: str,
        time_range: str = "24h",
        interval: str = "1h"
    ) -> List[Dict[str, Any]]:
        """Get event timeline for an index."""
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": {"bool": {"must": must_clauses}},
                    "aggs": {
                        "timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": interval,
                            }
                        }
                    }
                }
            )
            
            buckets = result["aggregations"]["timeline"]["buckets"]
            return [
                {
                    "timestamp": bucket["key_as_string"],
                    "count": bucket["doc_count"]
                }
                for bucket in buckets
            ]
        except Exception as e:
            logger.error("elasticsearch_timeline_failed", index=index, error=str(e))
            return []
    
    async def get_top_source_ips(
        self,
        index: str,
        time_range: str = "24h",
        size: int = 10,
        exclude_internal: bool = True
    ) -> List[Dict[str, Any]]:
        """Get top source IPs for an index, excluding internal IPs and noise."""
        src_ip_field = self._get_field(index, "src_ip")
        geo_country_field = self._get_field(index, "geo_country")
        geo_city_field = self._get_field(index, "geo_city")
        geo_location_field = self._get_field(index, "geo_location")
        
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if exclude_internal:
                query["bool"]["must_not"] = self._get_internal_ip_exclusion(index)
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": src_ip_field,
                                "size": size
                            },
                            "aggs": {
                                "geo": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": [geo_country_field, geo_city_field, geo_location_field]
                                    }
                                }
                            }
                        }
                    }
                }
            )
            
            buckets = result["aggregations"]["top_ips"]["buckets"]
            results = []
            
            for bucket in buckets:
                ip = bucket["key"]
                
                # Post-query filter for internal/private IPs
                if exclude_internal and is_internal_ip(ip):
                    continue
                    
                geo_data = {}
                if bucket["geo"]["hits"]["hits"]:
                    source = bucket["geo"]["hits"]["hits"][0]["_source"]
                    # Navigate nested structure to extract geo data
                    geo_data = self._extract_geo_data(source, index)
                
                results.append({
                    "ip": ip,
                    "count": bucket["doc_count"],
                    "geo": geo_data
                })
            
            return results
        except Exception as e:
            logger.error("elasticsearch_top_ips_failed", index=index, error=str(e))
            return []
    
    def _extract_geo_data(self, source: Dict[str, Any], index: str) -> Dict[str, Any]:
        """Extract geo data from nested source structure."""
        honeypot = self._get_honeypot_from_index(index)
        
        if honeypot == "cowrie":
            cowrie = source.get("cowrie", {})
            geo = cowrie.get("geo", {})
            return {
                "country_name": geo.get("country_name"),
                "city_name": geo.get("city_name"),
                "location": geo.get("location"),
            }
        else:
            # Standard ECS format: source.geo.*
            source_data = source.get("source", {})
            geo = source_data.get("geo", {})
            return {
                "country_name": geo.get("country_name"),
                "city_name": geo.get("city_name"),
                "location": geo.get("location"),
            }
    
    async def get_geo_distribution(
        self,
        index: str,
        time_range: str = "24h",
        size: int = 50,
        exclude_internal: bool = True
    ) -> List[Dict[str, Any]]:
        """Get geographic distribution of attacks, excluding internal IPs and noise."""
        geo_country_field = self._get_field(index, "geo_country")
        
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if exclude_internal:
                query["bool"]["must_not"] = self._get_internal_ip_exclusion(index)
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": {
                        "countries": {
                            "terms": {
                                "field": geo_country_field,
                                "size": size
                            }
                        }
                    }
                }
            )
            
            buckets = result["aggregations"]["countries"]["buckets"]
            return [
                {
                    "country": bucket["key"],
                    "count": bucket["doc_count"]
                }
                for bucket in buckets
            ]
        except Exception as e:
            logger.error("elasticsearch_geo_failed", index=index, error=str(e))
            return []
    
    async def get_recent_events(
        self,
        index: str,
        size: int = 50,
        fields: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Get recent events from an index."""
        try:
            body: Dict[str, Any] = {
                "size": size,
                "sort": [{"@timestamp": "desc"}],
            }
            
            if fields:
                body["_source"] = fields
            
            result = await self.client.search(index=index, body=body)
            
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error("elasticsearch_recent_events_failed", index=index, error=str(e))
            return []
    
    async def search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 100,
        sort: Optional[List[Dict[str, str]]] = None,
        aggs: Optional[Dict[str, Any]] = None,
        fields: Optional[List[str]] = None,
        from_: int = 0,
        track_total_hits: bool = False,
    ) -> Dict[str, Any]:
        """Execute a custom search query."""
        try:
            body: Dict[str, Any] = {
                "query": query,
                "size": size,
                "from": from_,
            }
            
            if sort:
                body["sort"] = sort
            if aggs:
                body["aggs"] = aggs
            if fields:
                body["_source"] = fields
            if track_total_hits:
                body["track_total_hits"] = True
            
            result = await self.client.search(index=index, body=body)
            return result
        except Exception as e:
            logger.error("elasticsearch_search_failed", index=index, error=str(e))
            return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}
    
    async def get_events_for_ip(
        self,
        ip: str,
        indices: Optional[List[str]] = None,
        time_range: str = "30d",
        size: int = 1000
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get all events for a specific IP across all honeypots."""
        if indices is None:
            indices = list(self.INDICES.values())
        
        results = {}
        
        for index in indices:
            try:
                src_ip_field = self._get_field(index, "src_ip")
                
                result = await self.client.search(
                    index=index,
                    body={
                        "size": size,
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {src_ip_field: ip}},
                                    self._get_time_range_query(time_range)
                                ]
                            }
                        },
                        "sort": [{"@timestamp": "desc"}]
                    }
                )
                
                events = [hit["_source"] for hit in result["hits"]["hits"]]
                if events:
                    # Extract honeypot name from index pattern
                    honeypot = self._get_honeypot_from_index(index)
                    results[honeypot] = events
            except Exception as e:
                logger.error("elasticsearch_ip_search_failed", index=index, ip=ip, error=str(e))
        
        return results
    
    async def get_hourly_heatmap(
        self,
        index: str,
        time_range: str = "7d"
    ) -> List[Dict[str, Any]]:
        """Get hourly heatmap data for an index."""
        try:
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": self._get_time_range_query(time_range),
                    "aggs": {
                        "by_day": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "calendar_interval": "day"
                            },
                            "aggs": {
                                "by_hour": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "calendar_interval": "hour"
                                    }
                                }
                            }
                        }
                    }
                }
            )
            
            heatmap_data = []
            for day_bucket in result["aggregations"]["by_day"]["buckets"]:
                day = day_bucket["key_as_string"]
                for hour_bucket in day_bucket["by_hour"]["buckets"]:
                    hour = datetime.fromisoformat(hour_bucket["key_as_string"].replace("Z", "+00:00")).hour
                    heatmap_data.append({
                        "day": day,
                        "hour": hour,
                        "count": hour_bucket["doc_count"]
                    })
            
            return heatmap_data
        except Exception as e:
            logger.error("elasticsearch_heatmap_failed", index=index, error=str(e))
            return []
    
    async def get_raw_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Get a raw document by ID."""
        try:
            # Use search with ids query for data stream compatibility
            result = await self.client.search(
                index=index,
                query={"ids": {"values": [doc_id]}},
                size=1
            )
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
            return None
        except Exception as e:
            logger.error("elasticsearch_get_document_failed", index=index, doc_id=doc_id, error=str(e))
            return None
    
    async def get_logs(
        self,
        index: str,
        time_range: str = "24h",
        size: int = 100,
        search_query: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get logs with optional search and filters."""
        must_clauses = [self._get_time_range_query(time_range)]
        
        if search_query:
            must_clauses.append({
                "query_string": {
                    "query": f"*{search_query}*",
                    "default_operator": "AND"
                }
            })
        
        if filters:
            for field, value in filters.items():
                if value is not None:
                    must_clauses.append({"term": {field: value}})
        
        try:
            result = await self.client.search(
                index=index,
                body={
                    "size": size,
                    "query": {"bool": {"must": must_clauses}},
                    "sort": [{"@timestamp": "desc"}]
                }
            )
            
            return {
                "total": result["hits"]["total"]["value"],
                "logs": [
                    {
                        "id": hit["_id"],
                        "index": hit["_index"],
                        **hit["_source"]
                    }
                    for hit in result["hits"]["hits"]
                ]
            }
        except Exception as e:
            logger.error("elasticsearch_logs_failed", index=index, error=str(e))
            return {"total": 0, "logs": []}
