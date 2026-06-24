import sys, os, json, subprocess, threading, queue
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context

app = Flask(__name__)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Lab definitions with ALL input fields ────────────────────────────────────

LABS = {
    "LAB-00": {
        "script": "00_foundations/agent_arch.py",
        "label": "Agentic AI Foundations",
        "description": "Traditional AI vs Agentic AI · Cognitive Loop · ReAct · Planning Paradigms",
        "inputs": [
            {
                "key": "GUI_Q1",
                "label": "Demo 1 — Comparison Question",
                "placeholder": "Compare Traditional AI vs Agentic AI across...",
                "default": "Compare Traditional AI Agents vs Modern Agentic AI Systems across: Autonomy, Goal Management, Adaptability, Decision Making, Tool Use, Memory. Format as a table then give one cybersecurity example for each.",
                "hint": "Change the domain — e.g. add 'in the context of IoT security' or 'for hospital SOC triage'",
                "type": "textarea"
            },
            {
                "key": "GUI_Q2",
                "label": "Demo 2 — SOC Alert (Cognitive Loop)",
                "placeholder": "Alert: Unusual outbound traffic...",
                "default": "Alert: Unusual outbound traffic to 185.220.101.5 from WS-042. Volume: 4.2 GB in 8 minutes.",
                "hint": "Write your own ambiguous alert — one with both a benign and a malicious explanation",
                "type": "textarea"
            },
            {
                "key": "GUI_Q3",
                "label": "Demo 3 — ReAct Task",
                "placeholder": "Investigate whether http://... is vulnerable to...",
                "default": "Demonstrate the ReAct paradigm for a PhD class. Task: Investigate whether http://localhost:8080 is vulnerable to SQL injection. Show exactly 3 Thought → Action → Observation cycles. Final Answer: [conclusion]",
                "hint": "Change the target URL or vulnerability type to test different ReAct reasoning",
                "type": "textarea"
            },
            {
                "key": "GUI_Q4",
                "label": "Demo 4 — Planning Scenario",
                "placeholder": "Scenario: Ransomware on 3 servers...",
                "default": "Teaching PhD students about AI planning in cybersecurity. Scenario: Ransomware alert on 3 servers in a hospital network. Show all three paradigms: STATIC, DYNAMIC, HIERARCHICAL (ASCII goal tree). Keep each section to 5-7 lines.",
                "hint": "Change the incident — e.g. DDoS attack, insider threat, supply chain compromise",
                "type": "textarea"
            },
        ]
    },
    "LAB-00b": {
        "script": "00_foundations/rag_demo.py",
        "label": "RAG vs Agentic RAG",
        "description": "Keyword retrieval vs reasoning-based retrieval on threat intel knowledge base",
        "inputs": [
            {
                "key": "GUI_INPUT_RAG_QUERY",
                "label": "Threat Intel Query",
                "placeholder": "We found a connection to 185.220.101.5 from our Flask web server",
                "default": "We found a connection to 185.220.101.5 from our Flask web server. Is it compromised?",
                "hint": "The query sent to both Traditional RAG and Agentic RAG",
                "type": "textarea"
            }
        ]
    },
    "LAB-01": {
        "script": "01_cobalt_flow/scout_agent.py",
        "label": "Scout Agent",
        "description": "Port scan → Web enumeration → Exploitability decision → Breacher handoff",
        "inputs": [
            {
                "key": "GUI_SCOUT_TARGET",
                "label": "Target",
                "placeholder": "Flask Lab Target",
                "default": "Flask Lab Target",
                "hint": "Scope-locked to lab Docker containers only",
                "type": "select",
                "options": ["Flask Lab Target", "WebGoat", "DVWA"]
            },
            {
                "key": "GUI_SCOUT_OBJECTIVE",
                "label": "Scout Objective",
                "placeholder": "Identify exploitable entry points...",
                "default": "Identify exploitable entry points and assess attack surface",
                "hint": "Change focus — e.g. authentication weaknesses only",
                "type": "textarea"
            },
        ]
    },
    "LAB-01b": {
        "script": "01_cobalt_flow/breacher_sim.py",
        "label": "Breacher Pipeline",
        "description": "Webhook → Payload select → Real SQLi → Validation → Simulated persistence",
        "inputs": [
            {
                "key": "GUI_BREACHER_TARGET",
                "label": "Target",
                "placeholder": "Flask Lab Target",
                "default": "Flask Lab Target",
                "hint": "Scope-locked to lab Docker containers only",
                "type": "select",
                "options": ["Flask Lab Target", "WebGoat", "DVWA"]
            },
            {
                "key": "GUI_BREACHER_TECHNIQUE",
                "label": "Exploit Technique",
                "placeholder": "sql_injection",
                "default": "sql_injection",
                "hint": "Choose which payload the Breacher fires",
                "type": "select",
                "options": ["sql_injection", "xss"]
            },
        ]
    },
    "LAB-02": {
        "script": "02_langgraph_agent/run_agent.py",
        "label": "Full Pentest Agent",
        "description": "Five-phase LangGraph agent: recon → enum → vuln assess → exploit → report",
        "inputs": [
            {
                "key": "GUI_INPUT_TARGET_URL",
                "label": "Target URL",
                "placeholder": "http://172.20.0.10:8080",
                "default": "http://172.20.0.10:8080",
                "hint": "Scope-locked to lab Docker targets only",
                "type": "text"
            }
        ]
    },
    "LAB-03": {
        "script": "labs/LAB-03-react.py",
        "label": "ReAct Paradigm",
        "description": "Thought → Action → Observation cycles with real tools",
        "inputs": [
            {
                "key": "GUI_INPUT_REACT_TARGET",
                "label": "Target URL to Test",
                "placeholder": "http://172.20.0.10:8080",
                "default": "http://172.20.0.10:8080",
                "hint": "ReAct agent will enumerate and test this URL",
                "type": "text"
            }
        ]
    },
    "LAB-04": {
        "script": "labs/LAB-04-rag.py",
        "label": "RAG and Agentic RAG",
        "description": "Compare keyword retrieval vs agentic reasoning across threat intel",
        "inputs": [
            {
                "key": "GUI_INPUT_RAG_QUERY",
                "label": "Threat Intel Query",
                "placeholder": "What CVEs affect our Flask server?",
                "default": "Our Flask server contacted 185.220.101.5. What happened?",
                "hint": "Query sent to both traditional and agentic RAG pipelines",
                "type": "textarea"
            }
        ]
    },
    "LAB-05": {
        "script": "labs/LAB-05-shodan.py",
        "label": "Shodan OSINT Agent",
        "description": "Real Shodan queries — passive intelligence gathering",
        "inputs": [
            {
                "key": "GUI_INPUT_SHODAN_QUERY",
                "label": "Shodan Search Query",
                "placeholder": 'product:"Werkzeug httpd"',
                "default": 'product:"Werkzeug httpd" "Werkzeug Debugger"',
                "hint": "Shodan query syntax — searches publicly indexed internet data",
                "type": "text"
            },
            {
                "key": "GUI_INPUT_INSTITUTION_QUERY",
                "label": "Your Institution Query (Task 3)",
                "placeholder": 'org:"University of Example"',
                "default": 'org:"University of Example"',
                "hint": "Replace with your actual institution name for Task 3",
                "type": "text"
            }
        ]
    },
    "LAB-06": {
        "script": "labs/LAB-06-passive-recon.py",
        "label": "Passive Recon Agent",
        "description": "DNS enumeration · WHOIS · Certificate transparency logs",
        "inputs": [
            {
                "key": "GUI_INPUT_RECON_DOMAIN",
                "label": "Primary Target Domain (Exercise 1 + Task 1)",
                "placeholder": "iiita.ac.in",
                "default": "iiita.ac.in",
                "hint": "Used for Exercise 1 and Task 1 — DNS/WHOIS/CT logs only, zero contact with target",
                "type": "text"
            },
            {
                "key": "GUI_INPUT_COMPARE_A",
                "label": "Task 2 — Domain A (compare)",
                "placeholder": "apache.org",
                "default": "apache.org",
                "hint": "First domain for Task 2 side-by-side comparison",
                "type": "text"
            },
            {
                "key": "GUI_INPUT_COMPARE_B",
                "label": "Task 2 — Domain B (compare)",
                "placeholder": "nginx.org",
                "default": "nginx.org",
                "hint": "Second domain for Task 2 side-by-side comparison",
                "type": "text"
            },
        ]
    },
    "LAB-07": {
        "script": "labs/LAB-07-pipeline-trace.py",
        "label": "Full Attack Pipeline",
        "description": "Five-phase attack trace with defender detection annotations",
        "inputs": [
            {
                "key": "GUI_INPUT_APPROVE_EXPLOIT",
                "label": "Approve Exploitation? (Task 2)",
                "placeholder": "yes or no",
                "default": "no",
                "hint": "Controls whether Task 2 runs real exploitation against lab target",
                "type": "select",
                "options": ["no", "yes"]
            }
        ]
    },
    "LAB-08": {
        "script": "labs/LAB-08-agent-custom.py",
        "label": "Agent Customisation",
        "description": "Change objectives → observe how findings change",
        "inputs": [
            {
                "key": "GUI_INPUT_AGENT_FOCUS",
                "label": "Agent Focus",
                "placeholder": "general",
                "default": "general",
                "hint": "Choose what the agent focuses on during assessment",
                "type": "select",
                "options": ["general", "authentication", "injection", "headers"]
            }
        ]
    },
    "LAB-09": {
        "script": "labs/LAB-09-governance.py",
        "label": "Scope & Governance",
        "description": "Prompt layer vs tool layer enforcement · Rate limiting · Confidence thresholds",
        "inputs": [
            {
                "key": "GUI_INPUT_TEST_TARGET",
                "label": "Test Target (scope check)",
                "placeholder": "google.com",
                "default": "google.com",
                "hint": "Enter an out-of-scope target to see scope enforcement fire",
                "type": "text"
            }
        ]
    },
    "LAB-10": {
        "script": "labs/LAB-10-research.py",
        "label": "Research Proposal",
        "description": "Convert lab observations into publishable research directions",
        "inputs": [
            {
                "key": "GUI_INPUT_RESEARCH_INTEREST",
                "label": "Your Research Interest",
                "placeholder": "I research adversarial machine learning...",
                "default": "I research adversarial machine learning — specifically how attackers manipulate ML model outputs by poisoning training data.",
                "hint": "Describe your existing research area — the LLM will connect it to agentic AI security",
                "type": "textarea"
            }
        ]
    },
    "LAB-HITL": {
        "script": "06_hitl_governance/hitl_breakpoint.py",
        "label": "Human-in-the-Loop",
        "description": "interrupt_before exploit node — operator must approve before agent continues",
        "inputs": [
            {
                "key": "GUI_INPUT_\nPROCEED_WITH_EXPLOITATION__YES_NO__",
                "label": "Approve Exploitation?",
                "placeholder": "yes or no",
                "default": "no",
                "hint": "Typed at the HITL breakpoint — agent is paused waiting for this",
                "type": "select",
                "options": ["no", "yes"]
            }
        ]
    },
}

# ── HTML Template ─────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Agentic Pentest Lab Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;height:100vh;display:flex;flex-direction:column;overflow:hidden}

header{background:#161b22;border-bottom:2px solid #21262d;padding:12px 20px;display:flex;align-items:center;gap:12px;flex-shrink:0}
header h1{font-size:16px;color:#58a6ff;font-weight:700}
.hbadge{font-size:11px;color:#8b949e;background:#21262d;padding:3px 10px;border-radius:12px;border:1px solid #30363d}
.hbadge.green{color:#3fb950;border-color:#3fb950;background:#0d2118}
.ml{margin-left:auto;display:flex;gap:8px;align-items:center}

.main{display:flex;flex:1;overflow:hidden}

/* SIDEBAR */
.sidebar{width:230px;background:#161b22;border-right:1px solid #21262d;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.sidebar-hdr{padding:12px 14px 8px;font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #21262d;flex-shrink:0}
.sidebar-list{flex:1;overflow-y:auto;padding:6px}
.lb{width:100%;text-align:left;background:none;border:1px solid #21262d;color:#c9d1d9;padding:9px 11px;margin-bottom:4px;border-radius:6px;cursor:pointer;transition:all 0.12s}
.lb:hover{background:#21262d;border-color:#30363d}
.lb.active{background:#0d2657;border-color:#58a6ff}
.lb .lid{font-size:10px;color:#6e7681;font-family:monospace;display:flex;align-items:center;gap:5px;margin-bottom:2px}
.lb .lname{font-size:12px;color:#e6edf3;font-weight:500}
.lb.active .lname{color:#79c0ff}
.lb .ldesc{font-size:10px;color:#6e7681;margin-top:4px;line-height:1.4;display:none}
.lb.active .ldesc{display:block}
.itag{font-size:9px;background:#1a3450;color:#58a6ff;padding:1px 5px;border-radius:8px;border:1px solid #2d5a8e}

/* CONTENT */
.content{flex:1;display:flex;flex-direction:column;overflow:hidden}

/* TOOLBAR */
.toolbar{background:#161b22;border-bottom:1px solid #21262d;padding:10px 16px;display:flex;align-items:center;gap:10px;flex-shrink:0}
.lab-info{flex:1;min-width:0}
.lab-info h2{font-size:13px;color:#e6edf3;font-weight:600}
.lab-info p{font-size:11px;color:#6e7681;margin-top:2px}
.run-btn{background:#238636;color:#fff;border:none;padding:7px 18px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;transition:background 0.15s;flex-shrink:0}
.run-btn:hover{background:#2ea043}
.run-btn:disabled{background:#21262d;color:#6e7681;cursor:not-allowed}
.stop-btn{background:#b62324;color:#fff;border:none;padding:7px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;display:none;flex-shrink:0}
.stop-btn:hover{background:#da3633}
.clr-btn{background:none;border:1px solid #30363d;color:#8b949e;padding:7px 12px;border-radius:6px;cursor:pointer;font-size:11px;flex-shrink:0}
.clr-btn:hover{color:#c9d1d9;border-color:#6e7681}
.dot{width:8px;height:8px;border-radius:50%;background:#30363d;flex-shrink:0}
.dot.running{background:#f0883e;animation:blink 0.8s infinite}
.dot.done{background:#3fb950}
.dot.error{background:#f85149}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
.stxt{font-size:11px;color:#8b949e;white-space:nowrap}

/* INPUT PANEL - always visible when lab has inputs */
.input-config{background:#161b22;border-bottom:1px solid #21262d;padding:12px 16px;display:none;flex-shrink:0}
.input-config.visible{display:block}
.input-config-title{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
.input-grid{display:grid;grid-template-columns:repeat(auto-fill, minmax(280px, 1fr));gap:10px}
.input-field{display:flex;flex-direction:column;gap:4px}
.input-field label{font-size:11px;color:#8b949e;font-weight:500}
.input-field .hint{font-size:10px;color:#6e7681;margin-top:2px}
.input-field input,.input-field textarea,.input-field select{
  background:#0d1117;border:1px solid #30363d;color:#c9d1d9;
  padding:7px 10px;border-radius:6px;font-size:12px;
  font-family:'Segoe UI',sans-serif;outline:none;width:100%;
  transition:border-color 0.15s
}
.input-field input:focus,.input-field textarea:focus,.input-field select:focus{border-color:#58a6ff}
.input-field textarea{resize:vertical;min-height:60px;max-height:120px}
.input-field select option{background:#161b22}

/* STEP TRACKER */
.steps-bar{background:#0d1117;border-bottom:1px solid #21262d;padding:7px 16px;display:flex;gap:5px;align-items:center;flex-shrink:0;overflow-x:auto;min-height:34px}
.step{font-size:10px;padding:2px 9px;border-radius:10px;border:1px solid #30363d;color:#6e7681;white-space:nowrap;transition:all 0.2s}
.step.active{background:#1a3450;border-color:#58a6ff;color:#58a6ff;font-weight:600}
.step.done{background:#0d2118;border-color:#3fb950;color:#3fb950}
.step.error{background:#2d0f0f;border-color:#f85149;color:#f85149}
.step-arrow{color:#30363d;font-size:10px}
.steps-label{font-size:10px;color:#6e7681;margin-right:4px;white-space:nowrap;flex-shrink:0}

/* OUTPUT */
.output-wrap{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative}
.output-area{flex:1;overflow-y:auto;padding:14px 18px;background:#0d1117;font-family:'Courier New',monospace;font-size:12px;line-height:1.7}

/* RUNTIME INPUT PROMPT */
.runtime-input{background:#1a1f0a;border-top:2px solid #e3b341;padding:12px 16px;display:none;flex-shrink:0}
.runtime-input.visible{display:block}
.ri-label{font-size:11px;color:#e3b341;margin-bottom:8px;font-weight:600;display:flex;align-items:center;gap:6px}
.ri-row{display:flex;gap:8px;align-items:center}
.ri-row input,.ri-row select{
  flex:1;background:#0d1117;border:2px solid #e3b341;
  color:#e6edf3;padding:8px 12px;border-radius:6px;
  font-size:13px;font-family:monospace;outline:none
}
.ri-row input:focus,.ri-row select:focus{border-color:#f0c046}
.ri-send{background:#e3b341;color:#0d1117;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700;flex-shrink:0}
.ri-send:hover{background:#f0c046}
.ri-hint{font-size:10px;color:#6e7681;margin-top:6px}

/* placeholder */
.ph{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#30363d;gap:12px;text-align:center}
.ph .icon{font-size:40px}
.ph p{font-size:13px;color:#6e7681}

/* line colours */
.c-blue{color:#58a6ff}.c-cyan{color:#79c0ff}.c-orange{color:#f0883e}
.c-red{color:#f85149}.c-green{color:#3fb950}.c-purple{color:#d2a8ff}
.c-yellow{color:#e3b341}.c-dim{color:#30363d}.c-white{color:#e6edf3;font-weight:600}
.c-input-echo{color:#e3b341;font-style:italic}
.c-phase{color:#79c0ff;font-weight:600}
</style>
</head>
<body>

<header>
  <h1>⚡ Agentic Pentest Lab Dashboard</h1>
  <span class="hbadge">GitHub Codespace</span>
  <span class="hbadge green">🎯 172.20.0.10:8080</span>
  <div class="ml">
    <span class="hbadge" id="timer-badge">00:00</span>
    <span class="hbadge" id="hstatus">Idle</span>
  </div>
</header>

<div class="main">

  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="sidebar-hdr">Lab Modules</div>
    <div class="sidebar-list">
      {% for lab_id, lab in labs.items() %}
      <button class="lb" onclick="selectLab('{{ lab_id }}')" id="btn-{{ lab_id }}">
        <div class="lid">
          {{ lab_id }}
          {% if lab.inputs %}<span class="itag">{{ lab.inputs|length }} INPUT{% if lab.inputs|length > 1 %}S{% endif %}</span>{% endif %}
        </div>
        <div class="lname">{{ lab.label }}</div>
        <div class="ldesc">{{ lab.description }}</div>
      </button>
      {% endfor %}
    </div>
  </div>

  <!-- CONTENT -->
  <div class="content">

    <!-- TOOLBAR -->
    <div class="toolbar">
      <div class="lab-info">
        <h2 id="lab-title">Select a lab module</h2>
        <p id="lab-desc-t">Click any lab in the sidebar to load it</p>
      </div>
      <div class="dot" id="dot"></div>
      <span class="stxt" id="stxt">Idle</span>
      <button class="clr-btn" onclick="clearAll()">Clear</button>
      <button class="stop-btn" id="stop-btn" onclick="stopLab()">■ Stop</button>
      <button class="run-btn" id="run-btn" onclick="runLab()" disabled>▶ Run Lab</button>
    </div>

    <!-- INPUT CONFIG PANEL (shown before run) -->
    <div class="input-config" id="input-config">
      <div class="input-config-title">⚙ Lab Inputs — configure before running</div>
      <div class="input-grid" id="input-grid"></div>
    </div>

    <!-- STEP TRACKER -->
    <div class="steps-bar" id="steps-bar">
      <span class="steps-label">Steps:</span>
      <span style="font-size:11px;color:#30363d">— select a lab —</span>
    </div>

    <!-- OUTPUT + RUNTIME INPUT -->
    <div class="output-wrap">
      <div class="output-area" id="output-area">
        <div class="ph" id="ph">
          <div class="icon">🔬</div>
          <p>Select a lab and configure inputs, then click ▶ Run Lab</p>
        </div>
      </div>

      <!-- RUNTIME INPUT (appears when script calls input()) -->
      <div class="runtime-input" id="runtime-input">
        <div class="ri-label">⚠️ <span id="ri-label-txt">Lab is waiting for your input</span></div>
        <div class="ri-row">
          <input type="text" id="ri-input" onkeydown="if(event.key==='Enter')sendRuntimeInput()"/>
          <button class="ri-send" onclick="sendRuntimeInput()">Send ↵</button>
        </div>
        <div class="ri-hint" id="ri-hint">Type your response and press Enter to continue the lab</div>
      </div>
    </div>

  </div>
</div>

<script>
const LABS = {{ labs_json | safe }};
let selectedLab = null;
let sessionId = null;
let evtSource = null;
let timerInt = null;
let startTs = null;
let lineCount = 0;

const STEP_DEFS = {
  'LAB-00':  ['AI Comparison','Cognitive Loop','ReAct','Planning'],
  'LAB-00b': ['Traditional RAG','Agentic RAG','Key Insight'],
  'LAB-01':  ['Port Scan','Web Enum','Decision','Handoff'],
  'LAB-01b': ['Webhook','Payload','HTTP Request','Validation','Persistence','Post-Exploit'],
  'LAB-02':  ['Reconnaissance','Vuln Assessment','Report','Complete'],
  'LAB-03':  ['Thought 1','Action 1','Obs 1','Thought 2','Action 2','Obs 2','Final Answer'],
  'LAB-04':  ['Keyword RAG','Agentic RAG','Hallucination Test'],
  'LAB-05':  ['Shodan Query','LLM Analysis','Institutional Query'],
  'LAB-06':  ['DNS Enum','WHOIS','CT Logs','LLM Synthesis'],
  'LAB-07':  ['Phase 1 OSINT','Phase 2 Recon','Phase 3 Exploit','Phase 4 Persist','Phase 5 Exfil'],
  'LAB-08':  ['Default Objectives','Auth Objectives','Compare Reports'],
  'LAB-09':  ['Prompt Layer Test','Tool Layer Test','Rate Limiter','Confidence Threshold'],
  'LAB-10':  ['Gap Identification','Hypothesis','Proposal Draft','Experiments'],
  'LAB-HITL':['Recon','Assessment','⚠️ HITL Pause','Exploitation','Report'],
};

const STEP_TRIGGERS = {
  'LAB-00':  ['DEMO 1','DEMO 2','DEMO 3','DEMO 4'],
  'LAB-00b': ['TRADITIONAL RAG','AGENTIC RAG','Key insight'],
  'LAB-01':  ['Phase 1','Phase 2','Phase 3','Phase 4'],
  'LAB-01b': ['Webhook trigger','Payload generator','HTTP request node','Validation node','Persistence node','Post-exploitation'],
  'LAB-02':  ['Phase: Reconnaissance','Phase: Vulnerability','Phase: Report','Completed in'],
  'LAB-03':  ['Thought 1','Action 1','Observation 1','Thought 2','Action 2','Observation 2','Final Answer'],
  'LAB-04':  ['TRADITIONAL RAG','AGENTIC RAG','hallucination'],
  'LAB-05':  ['Shodan query','Intelligence analysis','Institutional'],
  'LAB-06':  ['DNS','WHOIS','certificate','Infrastructure overview'],
  'LAB-07':  ['PHASE 1','PHASE 2','PHASE 3','PHASE 4','PHASE 5'],
  'LAB-08':  ['Default objectives','Authentication','Compare'],
  'LAB-09':  ['Prompt-layer','Tool-layer','Rate limit','Confidence'],
  'LAB-10':  ['Gap','Hypothesis','Proposal','Experiments'],
  'LAB-HITL':['Running recon','Testing endpoint','HUMAN APPROVAL','Approval granted','REPORT'],
};

// ── Lab selection ────────────────────────────────────────────────────────────

function selectLab(id) {
  stopLab();
  document.querySelectorAll('.lb').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + id).classList.add('active');
  selectedLab = id;
  const lab = LABS[id];
  document.getElementById('lab-title').textContent = id + ' — ' + lab.label;
  document.getElementById('lab-desc-t').textContent = lab.description;
  document.getElementById('run-btn').disabled = false;
  renderInputPanel(id);
  buildSteps(id);
  clearOutput();
}

// ── Input panel rendering ────────────────────────────────────────────────────

function renderInputPanel(id) {
  const lab = LABS[id];
  const panel = document.getElementById('input-config');
  const grid = document.getElementById('input-grid');

  if (!lab.inputs || lab.inputs.length === 0) {
    panel.classList.remove('visible');
    return;
  }

  panel.classList.add('visible');
  grid.innerHTML = '';

  lab.inputs.forEach(inp => {
    const div = document.createElement('div');
    div.className = 'input-field';

    let fieldHtml = '';
    if (inp.type === 'textarea') {
      fieldHtml = `<textarea id="inp-${inp.key}" placeholder="${inp.placeholder || ''}">${inp.default || ''}</textarea>`;
    } else if (inp.type === 'select') {
      const opts = (inp.options || []).map(o =>
        `<option value="${o}" ${o === inp.default ? 'selected' : ''}>${o}</option>`
      ).join('');
      fieldHtml = `<select id="inp-${inp.key}">${opts}</select>`;
    } else {
      fieldHtml = `<input type="text" id="inp-${inp.key}" placeholder="${inp.placeholder || ''}" value="${inp.default || ''}"/>`;
    }

    div.innerHTML = `
      <label>${inp.label}</label>
      ${fieldHtml}
      <span class="hint">${inp.hint || ''}</span>
    `;
    grid.appendChild(div);
  });
}

function collectInputEnv() {
  if (!selectedLab) return {};
  const lab = LABS[selectedLab];
  const env = {};
  (lab.inputs || []).forEach(inp => {
    const el = document.getElementById('inp-' + inp.key);
    if (el) env[inp.key] = el.value;
  });
  return env;
}

// ── Step tracker ─────────────────────────────────────────────────────────────

function buildSteps(id) {
  const bar = document.getElementById('steps-bar');
  const steps = STEP_DEFS[id] || [];
  if (!steps.length) {
    bar.innerHTML = '<span class="steps-label">Steps:</span><span style="font-size:11px;color:#30363d">auto-detected from output</span>';
    return;
  }
  let html = '<span class="steps-label">Steps:</span>';
  steps.forEach((s, i) => {
    if (i > 0) html += '<span class="step-arrow">›</span>';
    html += `<span class="step" id="step-${i}">${s}</span>`;
  });
  bar.innerHTML = html;
}

function updateStep(line) {
  if (!selectedLab) return;
  const triggers = STEP_TRIGGERS[selectedLab] || [];
  triggers.forEach((t, i) => {
    if (line.includes(t)) {
      triggers.forEach((_, j) => {
        const el = document.getElementById('step-' + j);
        if (!el) return;
        if (j < i) el.className = 'step done';
        else if (j === i) el.className = 'step active';
        else el.className = 'step';
      });
    }
  });
}

function markAllStepsDone() {
  (STEP_DEFS[selectedLab] || []).forEach((_, i) => {
    const el = document.getElementById('step-' + i);
    if (el) el.className = 'step done';
  });
}

// ── Output ───────────────────────────────────────────────────────────────────

function colorize(line) {
  const e = line.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  if (!e.trim()) return '';
  if (/^={4,}/.test(e)||/^-{4,}/.test(e)) return `<span class="c-dim">${e}</span>`;
  if (e.startsWith('>>> INPUT:'))            return `<span class="c-input-echo">${e}</span>`;
  if (e.includes('[AGENT] Phase:')||e.includes('Phase:')) return `<span class="c-phase">${e}</span>`;
  if (e.includes('[SCOUT]')||e.includes('[RECON]')||e.includes('Port scan')||e.includes('enumeration')) return `<span class="c-blue">${e}</span>`;
  if (e.includes('[VULN]')||e.includes('Vulnerable')||e.includes('CVSS')||e.includes('CWE-')) return `<span class="c-orange">${e}</span>`;
  if (e.includes('[EXPLOIT]')||e.includes('payload')||e.includes('SQL error')||e.includes('Success: True')) return `<span class="c-red">${e}</span>`;
  if (e.includes('[REPORT]')||e.includes('Executive Summary')||e.includes('Remediation')||e.includes('FINAL REPORT')) return `<span class="c-green">${e}</span>`;
  if (e.includes('[HITL]')||e.includes('HUMAN APPROVAL')||e.includes('BREAKPOINT')||e.includes('Approval')) return `<span class="c-yellow">${e}</span>`;
  if (e.includes('[AUDIT]')) return `<span class="c-purple">${e}</span>`;
  if (e.includes('SCOPE')||e.includes('BLOCKED')||e.includes('VIOLATION')) return `<span class="c-red">${e}</span>`;
  if (e.includes('[n8n]')||e.includes('Breacher')||e.includes('webhook')) return `<span class="c-purple">${e}</span>`;
  if (e.includes('Step 1')||e.includes('Step 2')||e.includes('Step 3')||e.includes('Step 4')) return `<span class="c-cyan">${e}</span>`;
  if (/^#{1,3} /.test(e)||e.includes('DEMO ')||e.includes('LAB ')) return `<span class="c-white">${e}</span>`;
  if (e.includes('complete')||e.includes('✅')) return `<span class="c-green">${e}</span>`;
  return e;
}

function appendLine(line) {
  const area = document.getElementById('output-area');
  const ph = document.getElementById('ph');
  if (ph) ph.remove();
  let pre = document.getElementById('out-pre');
  if (!pre) { pre = document.createElement('pre'); pre.id = 'out-pre'; area.appendChild(pre); }
  const colored = colorize(line);
  if (!colored) return;
  const div = document.createElement('div');
  div.innerHTML = colored;
  pre.appendChild(div);
  lineCount++;
  area.scrollTop = area.scrollHeight;
  updateStep(line);
}

function clearOutput() {
  lineCount = 0;
  document.getElementById('output-area').innerHTML =
    '<div class="ph" id="ph"><div class="icon">🔬</div><p>Click ▶ Run Lab to execute ' + (selectedLab||'selected lab') + '</p></div>';
  hideRuntimeInput();
}

function clearAll() {
  stopLab();
  clearOutput();
  setStatus('idle','Idle');
  document.getElementById('timer-badge').textContent = '00:00';
  stopTimer();
}

// ── Status / timer ───────────────────────────────────────────────────────────

function setStatus(state, txt) {
  document.getElementById('dot').className = 'dot' + (state !== 'idle' ? ' ' + state : '');
  document.getElementById('stxt').textContent = txt;
  document.getElementById('hstatus').textContent = txt;
}

function startTimer() {
  startTs = Date.now();
  timerInt = setInterval(() => {
    const s = Math.floor((Date.now() - startTs) / 1000);
    const m = Math.floor(s/60).toString().padStart(2,'0');
    document.getElementById('timer-badge').textContent = m + ':' + (s%60).toString().padStart(2,'0');
  }, 500);
}

function stopTimer() {
  if (timerInt) { clearInterval(timerInt); timerInt = null; }
}

// ── Runtime input panel ──────────────────────────────────────────────────────

function showRuntimeInput(prompt) {
  const panel = document.getElementById('runtime-input');
  panel.classList.add('visible');
  document.getElementById('ri-label-txt').textContent = prompt || 'Lab is waiting for your input';
  document.getElementById('ri-hint').textContent = 'Type your response and press Enter to continue the lab';
  document.getElementById('ri-input').value = '';
  document.getElementById('ri-input').focus();
  setStatus('running', 'Waiting for input...');
}

function hideRuntimeInput() {
  document.getElementById('runtime-input').classList.remove('visible');
  document.getElementById('ri-input').value = '';
}

async function sendRuntimeInput() {
  const val = document.getElementById('ri-input').value.trim();
  if (!val || !sessionId) return;
  hideRuntimeInput();
  appendLine('>>> INPUT: ' + val);
  setStatus('running', 'Running...');
  await fetch('/send_input', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({session_id: sessionId, input: val})
  });
}

// ── Run / Stop ───────────────────────────────────────────────────────────────

function runLab() {
  if (!selectedLab) return;
  clearOutput();
  sessionId = 'sess-' + Date.now();
  const env = collectInputEnv();

  setStatus('running','Running...');
  document.getElementById('run-btn').disabled = true;
  document.getElementById('stop-btn').style.display = 'inline-block';
  startTimer();

  appendLine('▶ ' + selectedLab + ' — ' + LABS[selectedLab].label);
  if (Object.keys(env).length) {
    appendLine('  Inputs: ' + JSON.stringify(env));
  }
  appendLine('');

  const params = new URLSearchParams({
    lab: selectedLab,
    session_id: sessionId,
    env: JSON.stringify(env)
  });

  evtSource = new EventSource('/stream?' + params.toString());

  evtSource.addEventListener('line', e => {
    appendLine(JSON.parse(e.data).text);
  });

  evtSource.addEventListener('input_needed', e => {
    showRuntimeInput(JSON.parse(e.data).prompt);
  });

  evtSource.addEventListener('done', e => {
    const data = JSON.parse(e.data);
    stopTimer();
    evtSource.close(); evtSource = null;
    document.getElementById('run-btn').disabled = false;
    document.getElementById('stop-btn').style.display = 'none';
    hideRuntimeInput();
    markAllStepsDone();
    appendLine('');
    appendLine(data.returncode === 0
      ? '✅ Complete — ' + lineCount + ' lines — ' + document.getElementById('timer-badge').textContent
      : '⚠️ Exited with code ' + data.returncode);
    setStatus(data.returncode === 0 ? 'done' : 'error',
              data.returncode === 0 ? 'Done ✓' : 'Error');
  });

  evtSource.onerror = () => {
    stopTimer();
    if (evtSource) { evtSource.close(); evtSource = null; }
    document.getElementById('run-btn').disabled = false;
    document.getElementById('stop-btn').style.display = 'none';
    setStatus('error','Connection lost');
    appendLine('❌ Stream connection lost');
  };
}

function stopLab() {
  if (evtSource) { evtSource.close(); evtSource = null; }
  if (sessionId) {
    fetch('/stop',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session_id:sessionId})});
    sessionId = null;
  }
  stopTimer();
  document.getElementById('run-btn').disabled = (selectedLab === null);
  document.getElementById('stop-btn').style.display = 'none';
  hideRuntimeInput();
  setStatus('idle','Stopped');
}

document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') runLab();
  if (e.key === 'Escape') stopLab();
});
</script>
</body>
</html>"""


# ── Session management ────────────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.q = queue.Queue()
        self.input_q = queue.Queue()
        self.proc = None
        self.done = False

sessions = {}
sessions_lock = threading.Lock()

def get_session(sid):
    with sessions_lock:
        if sid not in sessions:
            sessions[sid] = Session()
        return sessions[sid]

def cleanup(sid):
    with sessions_lock:
        sess = sessions.pop(sid, None)
    if sess and sess.proc:
        try: sess.proc.terminate()
        except: pass


# ── Input prompt detection ────────────────────────────────────────────────────

INPUT_TRIGGERS = [
    "proceed with exploitation",
    "approve exploitation",
    "(yes/no)",
    "yes/no",
    "enter your choice",
    "press enter",
    "type your",
    ": $",
]

def is_input_prompt(line):
    lo = line.lower()
    return any(t in lo for t in INPUT_TRIGGERS)


# ── Runner thread ─────────────────────────────────────────────────────────────

def runner_thread(sid, script_path, extra_env):
    sess = get_session(sid)
    try:
        env = {**os.environ, "PYTHONUNBUFFERED": "1", **extra_env}
        proc = subprocess.Popen(
            [sys.executable, "-u", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            cwd=BASE,
            env=env,
            text=True,
            bufsize=1,
        )
        sess.proc = proc

        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if is_input_prompt(line):
                sess.q.put(("input_needed", line))
                try:
                    user_input = sess.input_q.get(timeout=300)
                    proc.stdin.write(user_input + "\n")
                    proc.stdin.flush()
                except queue.Empty:
                    proc.terminate()
                    break
            else:
                sess.q.put(("line", line))

        proc.wait()
        sess.q.put(("done", proc.returncode))

    except Exception as ex:
        sess.q.put(("line", f"ERROR: {ex}"))
        sess.q.put(("done", 1))
    finally:
        sess.done = True


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML, labs=LABS, labs_json=json.dumps(LABS))


@app.route("/stream")
def stream():
    lab_id = request.args.get("lab")
    sid = request.args.get("session_id")
    try:
        extra_env = json.loads(request.args.get("env", "{}"))
    except Exception:
        extra_env = {}

    if lab_id not in LABS:
        def err():
            yield 'event: done\ndata: {"returncode":1}\n\n'
        return Response(stream_with_context(err()), mimetype="text/event-stream")

    script_path = os.path.join(BASE, LABS[lab_id]["script"])
    sess = get_session(sid)
    threading.Thread(target=runner_thread, args=(sid, script_path, extra_env), daemon=True).start()

    def generate():
        while True:
            try:
                item = sess.q.get(timeout=1)
            except queue.Empty:
                if sess.done: break
                yield ": keepalive\n\n"
                continue

            kind, payload = item
            if kind == "line":
                yield f"event: line\ndata: {json.dumps({'text': payload})}\n\n"
            elif kind == "input_needed":
                yield f"event: input_needed\ndata: {json.dumps({'prompt': payload})}\n\n"
            elif kind == "done":
                yield f"event: done\ndata: {json.dumps({'returncode': payload})}\n\n"
                break

        cleanup(sid)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/send_input", methods=["POST"])
def send_input():
    data = request.json
    sid = data.get("session_id")
    val = data.get("input", "").strip()
    with sessions_lock:
        sess = sessions.get(sid)
    if sess:
        sess.input_q.put(val)
        return jsonify({"ok": True})
    return jsonify({"ok": False})


@app.route("/stop", methods=["POST"])
def stop():
    cleanup(request.json.get("session_id"))
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("=" * 55)
    print("  Agentic Pentest Lab Dashboard")
    print(f"  Base: {BASE}")
    print("  URL:  http://localhost:9000")
    print("=" * 55)
    app.run(host="0.0.0.0", port=9000, debug=False, threaded=True)
