"""
Lab Control Panel
Runs at http://localhost:5000
Allows instructors and participants to configure lab parameters via GUI
"""

from flask import Flask, render_template_string, request, jsonify
import subprocess, json, os

app = Flask(__name__)

# Default lab configuration
config = {
    "target": "http://172.20.0.10:8080",
    "task": "Investigate for SQL injection and XSS vulnerabilities",
    "shodan_query": 'product:"Werkzeug httpd" debug',
    "corruption_type": "C10",
    "model": "llama-3.3-70b-versatile",
    "temperature": 0,
    "authorised_targets": [
        "172.20.0.10",
        "172.20.0.20",
        "172.20.0.30"
    ]
}

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Agentic Pentest Lab — Control Panel</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #00ff88;
               max-width: 900px; margin: 40px auto; padding: 20px; }
        h1 { color: #00ff88; border-bottom: 1px solid #00ff88; }
        h2 { color: #88aaff; margin-top: 30px; }
        label { display: block; margin-top: 15px; color: #aaaaff; }
        input, select, textarea {
            width: 100%; padding: 8px; margin-top: 5px;
            background: #0d0d1a; color: #00ff88;
            border: 1px solid #00ff88; font-family: monospace;
            font-size: 14px; box-sizing: border-box;
        }
        textarea { height: 80px; resize: vertical; }
        button {
            margin-top: 20px; padding: 12px 30px;
            background: #00ff88; color: #0d0d1a;
            border: none; font-family: monospace;
            font-size: 16px; cursor: pointer; font-weight: bold;
        }
        button:hover { background: #88aaff; }
        .output {
            margin-top: 20px; padding: 15px;
            background: #0d0d1a; border: 1px solid #333;
            white-space: pre-wrap; min-height: 100px;
            max-height: 500px; overflow-y: auto;
        }
        .section {
            border: 1px solid #333; padding: 20px;
            margin-top: 20px; border-radius: 4px;
        }
        .warning { color: #ff4444; }
        .success { color: #00ff88; }
        select option { background: #0d0d1a; }
    </style>
</head>
<body>
    <h1>🔒 Agentic Pentest Lab — Control Panel</h1>
    <p>All actions are scoped to the isolated Docker network (172.20.0.0/24).
    No external targets are reachable from this lab environment.</p>

    <!-- Lab Configuration -->
    <div class="section">
        <h2>Lab Configuration</h2>

        <label>Target URL</label>
        <select id="target">
            <option value="http://172.20.0.10:8080">
                172.20.0.10 — Lab Flask App (SQLi + XSS)</option>
            <option value="http://172.20.0.20:8080/WebGoat">
                172.20.0.20 — OWASP WebGoat</option>
            <option value="http://172.20.0.30">
                172.20.0.30 — DVWA</option>
        </select>

        <label>Investigation Task</label>
        <textarea id="task">{{ config.task }}</textarea>

        <label>Model</label>
        <select id="model">
            <option value="llama-3.3-70b-versatile">
                Llama 3.3 70B (primary)</option>
            <option value="llama-3.1-8b-instant">
                Llama 3.1 8B (size comparison)</option>
            <option value="qwen/qwen3-32b">
                Qwen3 32B (cross-family)</option>
        </select>

        <label>Temperature</label>
        <select id="temperature">
            <option value="0">0 — Deterministic (paper primary)</option>
            <option value="0.7">0.7 — Stochastic (robustness check)</option>
        </select>

        <button onclick="runLab()">▶ Run Lab Exercise</button>
    </div>

    <!-- Shodan Configuration -->
    <div class="section">
        <h2>Shodan OSINT Query (LAB-05)</h2>

        <label>Shodan Query</label>
        <select id="shodan_preset" onchange="updateShodanQuery()">
            <option value='product:"Werkzeug httpd" debug'>
                Flask debug mode exposed</option>
            <option value="product:PostgreSQL port:5432">
                Exposed PostgreSQL databases</option>
            <option value="apache has_vuln:true">
                Apache servers with CVEs</option>
            <option value="custom">Custom query...</option>
        </select>
        <input type="text" id="shodan_query"
               value='product:"Werkzeug httpd" debug'
               placeholder="Enter custom Shodan query"/>

        <label>Institution name (for Task 3)</label>
        <input type="text" id="institution"
               placeholder='e.g. org:"University of Manchester"'/>

        <button onclick="runShodan()">▶ Run Shodan Query</button>
    </div>

    <!-- Research Experiment Configuration -->
    <div class="section">
        <h2>Corruption Experiment (Research)</h2>
        <p>Configure and run individual corruption trials.</p>

        <label>Corruption Type</label>
        <select id="corruption_type">
            <option value="C01">C01 — Impossible port count</option>
            <option value="C02">C02 — Contradictory vulnerability</option>
            <option value="C03">C03 — Wrong target IP</option>
            <option value="C04">C04 — Fabricated CVE</option>
            <option value="C05">C05 — Impossible CVSS score</option>
            <option value="C06">C06 — Empty response</option>
            <option value="C07">C07 — Credential leak</option>
            <option value="C08">C08 — Out of scope reference</option>
            <option value="C09">C09 — Contradictory server versions</option>
            <option value="C10" selected>C10 — Prompt injection via tool</option>
        </select>

        <label>Number of trials</label>
        <select id="trials">
            <option value="1">1 — Quick demo</option>
            <option value="3">3 — Pilot</option>
            <option value="10">10 — Full experiment</option>
        </select>

        <button onclick="runExperiment()">▶ Run Corruption Experiment</button>
    </div>

    <!-- Output -->
    <div class="section">
        <h2>Output</h2>
        <div class="output" id="output">
Ready. Configure above and click Run.
        </div>
    </div>

    <script>
        function updateShodanQuery() {
            const preset = document.getElementById('shodan_preset').value;
            if (preset !== 'custom') {
                document.getElementById('shodan_query').value = preset;
            }
        }

        async function runLab() {
            const output = document.getElementById('output');
            output.textContent = 'Running lab exercise...\\n';
            const response = await fetch('/run_lab', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    target: document.getElementById('target').value,
                    task: document.getElementById('task').value,
                    model: document.getElementById('model').value,
                    temperature: parseFloat(
                        document.getElementById('temperature').value),
                })
            });
            const data = await response.json();
            output.textContent = data.output || data.error;
        }

        async function runShodan() {
            const output = document.getElementById('output');
            output.textContent = 'Running Shodan query...\\n';
            const response = await fetch('/run_shodan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    query: document.getElementById('shodan_query').value,
                    institution: document.getElementById('institution').value,
                })
            });
            const data = await response.json();
            output.textContent = data.output || data.error;
        }

        async function runExperiment() {
            const output = document.getElementById('output');
            output.textContent = 'Running corruption experiment...\\n';
            const response = await fetch('/run_experiment', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    corruption_type: document.getElementById(
                        'corruption_type').value,
                    trials: parseInt(document.getElementById('trials').value),
                    model: document.getElementById('model').value,
                    temperature: parseFloat(
                        document.getElementById('temperature').value),
                })
            });
            const data = await response.json();
            output.textContent = data.output || data.error;
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML, config=config)

@app.route('/run_lab', methods=['POST'])
def run_lab():
    data = request.json
    target = data.get('target', '')

    # Scope enforcement — GUI cannot bypass this
    authorised = ['172.20.0.10', '172.20.0.20', '172.20.0.30']
    if not any(t in target for t in authorised):
        return jsonify({'error':
            f'SCOPE VIOLATION: {target} is not an authorised target.'})

    try:
        env = os.environ.copy()
        env['LLM_MODEL'] = data.get('model', 'llama-3.3-70b-versatile')
        env['LAB_TARGET'] = target
        env['LAB_TASK'] = data.get('task', '')

        result = subprocess.run(
            ['python', 'labs/LAB-03-react.py'],
            capture_output=True, text=True, timeout=120, env=env
        )
        output = result.stdout or result.stderr
        return jsonify({'output': output[:5000]})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timeout — lab took too long'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/run_shodan', methods=['POST'])
def run_shodan():
    data = request.json
    query = data.get('query', '')
    institution = data.get('institution', '')

    # No scope enforcement needed for Shodan — passive only
    # But validate query length to prevent abuse
    if len(query) > 200:
        return jsonify({'error': 'Query too long'})

    try:
        env = os.environ.copy()
        env['SHODAN_QUERY_OVERRIDE'] = query
        env['SHODAN_INSTITUTION'] = institution

        result = subprocess.run(
            ['python', 'labs/LAB-05-shodan.py'],
            capture_output=True, text=True, timeout=60, env=env
        )
        return jsonify({'output': result.stdout[:5000] or result.stderr})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/run_experiment', methods=['POST'])
def run_experiment():
    data = request.json
    corruption_type = data.get('corruption_type', 'C10')
    trials = min(int(data.get('trials', 1)), 10)  # cap at 10
    model = data.get('model', 'llama-3.3-70b-versatile')
    temperature = float(data.get('temperature', 0))

    # Validate corruption type
    valid_types = [f'C{i:02d}' for i in range(1, 11)]
    if corruption_type not in valid_types:
        return jsonify({'error': f'Invalid corruption type: {corruption_type}'})

    try:
        env = os.environ.copy()
        env['LLM_MODEL'] = model

        result = subprocess.run(
            ['python', 'experiments/corruption_propagation_experiment.py',
             '--corruption-id', corruption_type,
             '--trials', str(trials)],
            capture_output=True, text=True, timeout=300, env=env
        )
        return jsonify({'output': result.stdout[:5000] or result.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Experiment timeout'})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("Lab Control Panel running at http://localhost:5000")
    print("All targets scoped to 172.20.0.0/24 — no external access")
    app.run(host='0.0.0.0', port=5000, debug=False)

@app.route('/run_lab_by_number', methods=['POST'])
def run_lab_by_number():
    data = request.json
    lab_num = int(data.get('lab_number', 3))
    
    # Map lab numbers to files
    lab_files = {
        1:  'labs/LAB-01-fundamentals.py',
        2:  'labs/LAB-02-cognitive-loop.py',
        3:  'labs/LAB-03-react.py',
        4:  'labs/LAB-04-rag.py',
        5:  'labs/LAB-05-shodan.py',
        6:  'labs/LAB-06-passive-recon.py',
        7:  'labs/LAB-07-pipeline-trace.py',
        8:  'labs/LAB-08-agent-custom.py',
        9:  'labs/LAB-09-governance.py',
        10: 'labs/LAB-10-research.py',
        11: 'labs/LAB-11-agent-skills.py',
        12: 'labs/LAB-12-reporting.py',
        13: 'labs/LAB-13-scope-audit.py',
        14: 'labs/LAB-14-hitl-extended.py',
    }
    
    if lab_num not in lab_files:
        return jsonify({'error': f'Lab {lab_num} not found'})
    
    lab_file = lab_files[lab_num]
    
    if not os.path.exists(lab_file):
        return jsonify({'error': f'File not found: {lab_file}'})
    
    try:
        env = os.environ.copy()
        env['LLM_MODEL'] = data.get('model', 'llama-3.3-70b-versatile')
        if data.get('target'):
            env['LAB_TARGET'] = data['target']
        
        result = subprocess.run(
            ['python', lab_file],
            capture_output=True, text=True,
            timeout=180, env=env
        )
        output = result.stdout or result.stderr
        return jsonify({'output': output[:8000]})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Lab timeout after 180 seconds'})
    except Exception as e:
        return jsonify({'error': str(e)})
