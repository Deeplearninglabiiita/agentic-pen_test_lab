# Lab Experiments

Run from the workspace root. Each lab is self-contained.

| Lab | Topic | Time | Run command |
|-----|-------|------|-------------|
| LAB-01 | Agentic AI Fundamentals | 15 min | `python labs/LAB-01-fundamentals.py` |
| LAB-02 | Cognitive Loop | 15 min | `python labs/LAB-02-cognitive-loop.py` |
| LAB-03 | ReAct and Tool Use | 20 min | `python labs/LAB-03-react.py` |
| LAB-04 | RAG and Knowledge Retrieval | 20 min | `python labs/LAB-04-rag.py` |
| LAB-05 | Shodan OSINT Agent | 20 min | `python labs/LAB-05-shodan.py` |
| LAB-06 | Passive Reconnaissance | 20 min | `python labs/LAB-06-passive-recon.py` |
| LAB-07 | Full Pipeline Trace | 20 min | `python labs/LAB-07-pipeline-trace.py` |
| LAB-08 | Agent Customisation | 20 min | `python labs/LAB-08-agent-custom.py` |
| LAB-09 | Governance and Safety | 20 min | `python labs/LAB-09-governance.py` |
| LAB-10 | Research Proposal | 20 min | `python labs/LAB-10-research.py` |

## Before running labs that use the target app

```bash
docker compose up -d
curl http://localhost:8080/api/status
```

## Edit the TODO sections

Every lab has clearly marked TODO sections. These are where you
change queries, objectives, targets, or add your own code.
Run the file first to see the default output, then edit and run again.
