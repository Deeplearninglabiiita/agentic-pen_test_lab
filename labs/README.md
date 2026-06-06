# Lab Experiments — Complete List

Run from the workspace root with virtual environment active.

## Quick reference

| Lab | File | Topic | Mirrors | Time |
|-----|------|-------|---------|------|
| 01 | LAB-01-fundamentals.py | Agentic AI vs Traditional AI | PPT slides 5-8 | 15 min |
| 02 | LAB-02-cognitive-loop.py | Perceive, Reason, Plan, Act | PPT slide 7 | 15 min |
| 03 | LAB-03-react.py | ReAct paradigm and tool use | PPT slide 8 | 20 min |
| 04 | LAB-04-rag.py | RAG and Agentic RAG | PPT slides 12-16 | 20 min |
| 05 | LAB-05-shodan.py | Real Shodan OSINT agent | Hour 2 Block 1 | 20 min |
| 06 | LAB-06-passive-recon.py | DNS, WHOIS, CT logs | Hour 2 Block 2 | 20 min |
| 07 | LAB-07-pipeline-trace.py | Full attack pipeline trace | Ch8 pp. 4-7 | 20 min |
| 08 | LAB-08-agent-custom.py | LangGraph agent customisation | Ch8 Ex 8-3/6 | 20 min |
| 09 | LAB-09-governance.py | Scope, rate limiting, confidence | Ch8 pp. 23-24 | 20 min |
| 10 | LAB-10-research.py | Research proposal writing | Hour 3 Block 3 | 20 min |
| 11 | LAB-11-agent-skills.py | Agent Skills and SKILL.md | Ch8 pp. 24-32 | 20 min |
| 12 | LAB-12-reporting.py | Multi-audience report generation | Ch8 pp. 30-31 | 20 min |
| 13 | LAB-13-scope-audit.py | Scope validation and audit trail | governance files | 15 min |
| 14 | LAB-14-hitl-extended.py | Extended HITL with breakpoints | Ch8 Ex 8-8 | 20 min |

## Before labs that need the Docker target (Labs 07, 08, 14)

```bash
docker compose up -d
curl http://localhost:8080/api/status
```

## Run a single lab

```bash
python labs/LAB-11-agent-skills.py
python labs/LAB-12-reporting.py
python labs/LAB-13-scope-audit.py
python labs/LAB-14-hitl-extended.py
```

## What to edit in each lab

Every lab has TODO sections. The pattern is always:
1. Run as-is — see the default output
2. Edit the TODO section — change query, target, or finding
3. Run again — compare the output
4. Answer the reflection questions at the end

## Session allocation

| Session hour | Labs to run |
|-------------|-------------|
| Hour 1 (foundations) | LAB-01, LAB-02, LAB-03, LAB-04 |
| Hour 2 (OSINT + attack) | LAB-05, LAB-06, LAB-07 |
| Hour 3 (agent + governance) | LAB-08, LAB-09, LAB-11, LAB-12, LAB-13, LAB-14 |
| Research discussion | LAB-10 |
