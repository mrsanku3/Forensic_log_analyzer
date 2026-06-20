# Forensic_log_analyzer
A high-speed digital forensics and data-engineering triage tool built for Cyber Cells and Law Enforcement Agencies (LEAs) to instantly ingest, normalize, and map massive TSP IPDR/CDR network logs, converting rows of raw connection data into actionable target matrices and visualization pathways.

# Law Enforcement IPDR Forensic Link Analyzer

## Operational Overview
In modern digital forensics, Law Enforcement Agencies and specialized Cyber Cells routinely obtain massive Internet Protocol Detail Record (IPDR) and Call Detail Record (CDR) spreadsheets from Telecom Service Providers during criminal investigations. These files frequently contain hundreds of thousands of rows of raw network traffic records. 

Manually parsing these spreadsheets to detect coordinated suspect communication networks, find structural overlaps, or isolate malicious Command and Control endpoints creates a significant operational bottleneck.

This Forensic Link Analyzer is a high-speed data engineering triage tool built to instantly ingest raw, unorganized CSV network logs. By cleaning background broadcast anomalies and executing fast memory-pointer vector aggregation, it automatically converts dense tables into an actionable, prioritized target matrix and a high-resolution communication plot. This enables investigators to map digital infrastructure and uncover hidden operational connections in seconds.

## Key Architecture and Features
* **High Performance Ingestion Layer:** Uses optimized processing pipelines capable of sweeping through large transaction datasets in under a second with absolute mathematical counting accuracy.
* **Dynamic Header Normalization:** Automatically maps disparate naming conventions used by different telecom providers, converting fields like Source IP, Source, or Destination seamlessly.
* **Automated Noise Mitigation:** Programmatically filters out localized loopback addresses and multi-cast network broadcast noise to minimize visual clutter and drastically reduce investigative false positives.
* **Target Priority Triage Matrix:** Ranks and indexes endpoints dynamically by interaction volume, pointing investigators directly to the highest-density nodes.
* **Tactical Layout:** Designed using an operational dark theme optimized for low-light environments typical of cyber cell operations.

## Technical Specifications and Dependencies
* **Core Language:** Python 3.11 or higher
* **Dashboard Interface:** Streamlit
* **Data Processing Engine:** Pandas 
* **Forensic Plotting Engine:** Matplotlib and Seaborn

## Installation and Local Execution

### 1. Clone the Repository
```bash
git clone [https://github.com/mrsanku3/ipdr-link-analyzer.git]
cd ipdr-link-analyzer
