# Enterprise-Security-Monitoring-Incident-Response-System
Build a cybersecurity monitoring and incident response system for enterprise-level security operations

version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
    container_name: siem-elasticsearch
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-ChangeMeStrongPass123!}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - es_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - soc_net

  logstash:
    image: docker.elastic.co/logstash/logstash:8.15.0
    container_name: siem-logstash
    volumes:
      - ./logstash/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    environment:
      - LS_JAVA_OPTS=-Xms1g -Xmx1g
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-ChangeMeStrongPass123!}
    ports:
      - "5044:5044"
      - "5140:5140/udp"
    depends_on:
      - elasticsearch
    networks:
      - soc_net

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.0
    container_name: siem-kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD:-ChangeMeStrongPass123!}
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - soc_net

  suricata:
    image: jasonish/suricata:latest
    container_name: siem-suricata
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_NICE
    volumes:
      - ./suricata/local.rules:/var/lib/suricata/rules/local.rules:ro
      - suricata_logs:/var/log/suricata
    command: -i eth0 -v

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.15.0
    container_name: siem-filebeat
    user: root
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - suricata_logs:/var/log/suricata:ro
    depends_on:
      - logstash
    networks:
      - soc_net

  thehive:
    image: strangebee/thehive:5.2
    container_name: soar-thehive
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms1g -Xmx2g
    volumes:
      - thehive_data:/opt/thp/thehive/data
    networks:
      - soc_net

volumes:
  es_data:
  suricata_logs:
  thehive_data:

networks:
  soc_net:
    driver: bridge


    filebeat.inputs:
  - type: filestream
    id: suricata-eve-logs
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    parsers:
      - ndjson:
          target: "suricata"
          add_error_key: true

output.logstash:
  hosts: ["logstash:5044"]


  input {
  beats {
    port => 5044
  }
  udp {
    port => 5140
    type => "syslog"
  }
}

filter {
  # Parse Firewall Syslog
  if [type] == "syslog" {
    grok {
      match => { 
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:firewall_host} %{WORD:action} %{WORD:protocol} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port}" 
      }
    }
    geoip {
      source => "src_ip"
      target => "source.geo"
    }
  }

  # Tag Windows Security Events
  if [winlog][event_id] == 4625 {
    mutate {
      add_field => { "threat.tactic.name" => "Credential Access" }
      add_field => { "threat.technique.id" => "T1110" }
      add_tag => ["failed_logon", "brute_force_candidate"]
    }
  }

  # Tag Suricata High-Severity Alerts
  if [suricata][alert][severity] == 1 {
    mutate {
      add_tag => ["critical_ids_alert", "soar_trigger"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    index => "enterprise-siem-%{+YYYY.MM.dd}"
  }
}


Suricata IDS Custom Rules (detection-rules/suricata/local.rules)
# 1. Detect Nmap SYN Scan
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap SYN Scan Detected"; flags:S,12; threshold: type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:1000001; rev:1;)

# 2. Detect PowerShell Encoded Command over HTTP
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Suspicious Encoded PowerShell Download"; content:"powershell"; nocase; content:"-enc"; nocase; distance:0; classtype:trojan-activity; sid:1000002; rev:1;)

# 3. Detect Potential DNS Tunneling (High Length Subdomain)
alert dns $HOME_NET any -> any 53 (msg:"POLICY Potential DNS Tunneling - Excessive Query Length"; dns.query; content:"."; pcre:"/^[a-zA-Z0-9]{50,}\./"; classtype:bad-unknown; sid:1000003; rev:1;)

# 4. Detect Internal SMB Lateral Movement (PsExec / Admin Share Access)
alert smb $HOME_NET any -> $HOME_NET 445 (msg:"LATERAL MOVEMENT Suspicious SMB ADMIN$ Share Access"; content:"ADMIN$"; nocase; classtype:policy-violation; sid:1000004; rev:1;)

Sigma Detection Rules (detection-rules/sigma-rules/)
detection-rules/sigma-rules/win_suspicious_powershell.yml

title: Encoded PowerShell Execution with Web Download
id: 8f9a1b2c-3d4e-5f6a-7b8c-9d0e1f2a3b4c
status: production
description: Detects suspicious PowerShell execution using encoded commands or web download cradles.
author: SOC Engineering Team
date: 2026/11/14
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cli:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - 'DownloadString'
      - 'Invoke-WebRequest'
      - 'IEX('
  condition: selection_img and selection_cli
falsepositives:
  - Legitimate administrative deployment scripts
level: high


title: LSASS Memory Access for Credential Dumping
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: production
description: Detects potential credential dumping via unauthorized process access to lsass.exe.
author: SOC Engineering Team
date: 2026/11/14
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x1fffff'
  filter_legitimate:
    SourceImage|startswith:
      - 'C:\Program Files\'
      - 'C:\Windows\System32\'
  condition: selection and not filter_legitimate
falsepositives:
  - Antivirus/EDR agents scanning LSASS
level: critical


PYTHON
import os
import time
import requests
from elasticsearch import Elasticsearch

# Configuration
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "ChangeMeStrongPass123!")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "your_abuseipdb_api_key")
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000/api/v1/case")
THEHIVE_KEY = os.getenv("THEHIVE_KEY", "your_thehive_api_key")

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))

def check_ip_reputation(ip_address):
    """Query AbuseIPDB for threat confidence score."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()
        return data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception as e:
        print(f"[ERROR] Threat intel lookup failed: {e}")
        return 0

def block_ip_on_firewall(ip_address):
    """Simulate API call to Next-Gen Firewall to block malicious IP."""
    print(f"[ACTION] Pushing dynamic block rule to Perimeter NGFW for IP: {ip_address}")
    # Example NGFW REST API call:
    # requests.post("https://ngfw.corp.local/api/v1/blocklist", json={"ip": ip_address}, verify=False)

def create_thehive_case(title, description, severity, observables):
    """Create an incident response ticket in TheHive."""
    headers = {
        "Authorization": f"Bearer {THEHIVE_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "title": title,
        "description": description,
        "severity": severity,
        "tlp": 2,
        "tags": ["Automated-SOAR", "SIEM-Alert"]
    }
    try:
        res = requests.post(THEHIVE_URL, json=payload, headers=headers, timeout=10)
        if res.status_code in [200, 201]:
            print(f"[SUCCESS] Created TheHive Case: {title}")
    except Exception as e:
        print(f"[ERROR] Failed to create TheHive case: {e}")

def run_soar_engine():
    print("[INFO] Starting Enterprise SOAR Auto-Responder...")
    processed_ids = set()

    while True:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"tags": "soar_trigger"}},
                        {"range": {"@timestamp": {"gte": "now-5m"}}}
                    ]
                }
            }
        }
        try:
            results = es.search(index="enterprise-siem-*", body=query)
            for hit in results["hits"]["hits"]:
                doc_id = hit["_id"]
                if doc_id in processed_ids:
                    continue

                source = hit["_source"]
                src_ip = source.get("src_ip") or source.get("suricata", {}).get("src_ip")
                alert_msg = source.get("suricata", {}).get("alert", {}).get("signature", "High Severity SIEM Alert")

                if src_ip:
                    score = check_ip_reputation(src_ip)
                    print(f"[INFO] Alert: '{alert_msg}' | Source IP: {src_ip} | Abuse Score: {score}%")

                    if score >= 75:
                        block_ip_on_firewall(src_ip)

                    create_thehive_case(
                        title=f"[SOAR] {alert_msg} from {src_ip}",
                        description=f"Automated detection triggered.\nSource IP: {src_ip}\nAbuseIPDB Score: {score}%\nContainment: {'IP Blocked' if score >= 75 else 'Manual Review Required'}",
                        severity=3 if score >= 75 else 2,
                        observables=[src_ip]
                    )

                processed_ids.add(doc_id)
        except Exception as e:
            print(f"[ERROR] SIEM query error: {e}")

        time.sleep(30)

if __name__ == "__main__":
    run_soar_engine()


    MARKDOWN
    # Enterprise Security Monitoring & Incident Response System

An end-to-end, containerized Security Operations Center (SOC) architecture combining **ELK Stack SIEM**, **Suricata Network IDS**, **Sigma Detection Rules**, and **Python SOAR Automation** integrated with **TheHive**.

## Architecture Overview
- **Log Ingestion:** Filebeat & Winlogbeat forward endpoint (Sysmon) and network telemetry to Logstash.
- **SIEM Core:** Elasticsearch indexes normalized ECS logs; Kibana provides real-time SOC dashboards.
- **Intrusion Detection:** Suricata inspects network traffic for reconnaissance, C2 beaconing, and lateral movement.
- **Automated Response (SOAR):** Python orchestration engine enriches alerts via AbuseIPDB, blocks malicious IPs on the perimeter firewall, and opens cases in TheHive.

## Quick Start Deployment

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/enterprise-siem-ir-system.git](https://github.com/yourusername/enterprise-siem-ir-system.git)
   cd enterprise-siem-ir-system/siem-configs

   BASH
   export ELASTIC_PASSWORD="YourStrongPassword123!"
export ABUSEIPDB_KEY="your_api_key"
export THEHIVE_KEY="your_thehive_key"

Launch the SIEM & IDS Stack:
docker-compose up -d

Start the SOAR Automation Engine:
pip install elasticsearch requests
python3 ../soar-workflows/auto_responder.py
