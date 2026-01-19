#!/usr/bin/env bash
# Enhanced Report Library for UASF
# Generates comprehensive HTML reports with statistics and visualizations

generate_enhanced_report() {
  local csv_file="${1:-}"
  local output_file="${2:-}"
  local target="${3:-unknown}"
  local cid="${4:-unknown}"
  local evidence_dir="${5:-./evidence}"
  
  # Validate inputs
  [[ -z "$csv_file" || ! -f "$csv_file" ]] && echo "Error: No CSV file" && return 1
  [[ -z "$output_file" ]] && output_file="./report.html"
  
  # Calculate statistics
  local total_requests pass_count block_count warn_count
  total_requests=$(tail -n +2 "$csv_file" 2>/dev/null | wc -l | tr -d ' ') || total_requests=0
  pass_count=$(grep -c ',PASS$' "$csv_file" 2>/dev/null) || pass_count=0
  block_count=$(grep -c ',BLOCK$' "$csv_file" 2>/dev/null) || block_count=0
  warn_count=$(grep -c ',WARN$' "$csv_file" 2>/dev/null) || warn_count=0
  
  # Calculate percentages
  local block_pct=0
  if [[ $total_requests -gt 0 ]]; then
    block_pct=$(awk "BEGIN {printf \"%.1f\", ($block_count/$total_requests)*100}")
  fi
  
  # Generate HTTP code distribution
  local codes
  codes=$(awk -F',' 'NR>1{c[$3]++} END{for(k in c) printf "<tr><td>%s</td><td>%d</td><td>%.1f%%</td></tr>\n",k,c[k],(c[k]/NR*100)}' "$csv_file" 2>/dev/null) || codes=""
  
  # Generate module statistics
  local mods
  mods=$(awk -F',' 'NR>1{m[$2]++; if($8=="BLOCK") b[$2]++} END{for(k in m) printf "<tr><td>%s</td><td>%d</td><td>%d</td><td>%.1f%%</td></tr>\n",k,m[k],b[k]+0,(b[k]+0)/m[k]*100}' "$csv_file" 2>/dev/null) || mods=""
  
  # Generate sample rows (first 100)
  local samples
  samples=$(awk -F',' 'NR>1 && NR<=101{
    gsub("&","\\&amp;",$7); gsub("<","\\&lt;",$7);
    verdict=$8;
    color="";
    if(verdict=="BLOCK") color="#ff4444";
    else if(verdict=="PASS") color="#44ff44";
    else color="#ffaa44";
    printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td style=\"word-break:break-all;max-width:400px\">%s</td><td style=\"color:%s;font-weight:bold\">%s</td></tr>\n", $1,$2,$3,$4,$5,$6,$7,color,$8
  }' "$csv_file" 2>/dev/null) || samples=""
  
  # Count evidence files
  local evidence_count=0
  if [[ -d "$evidence_dir" ]]; then
    evidence_count=$(ls -1 "$evidence_dir" 2>/dev/null | wc -l | tr -d ' ') || evidence_count=0
  fi
  
  cat > "$output_file" <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UASF Report - ${target}</title>
<style>
:root {
  --bg: #0f0f23;
  --card: #1a1a2e;
  --border: #2a2a4e;
  --text: #e0e0e0;
  --accent: #00d4ff;
  --success: #00ff88;
  --danger: #ff4466;
  --warning: #ffaa00;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 24px;
}
.container { max-width: 1400px; margin: 0 auto; }
header {
  background: linear-gradient(135deg, #1e3a5f 0%, #0f1f33 100%);
  border-radius: 12px;
  padding: 32px;
  margin-bottom: 24px;
  border: 1px solid var(--border);
}
h1 { color: var(--accent); font-size: 2rem; margin-bottom: 8px; }
h2 { color: var(--accent); font-size: 1.4rem; margin: 24px 0 16px; }
h3 { color: var(--text); font-size: 1.1rem; margin: 16px 0 12px; }
.meta { color: #888; font-size: 0.9rem; }
.meta strong { color: var(--text); }
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin: 24px 0;
}
.stat-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.stat-value { font-size: 2.5rem; font-weight: bold; }
.stat-label { color: #888; font-size: 0.85rem; text-transform: uppercase; }
.stat-card.block .stat-value { color: var(--danger); }
.stat-card.pass .stat-value { color: var(--success); }
.stat-card.warn .stat-value { color: var(--warning); }
.stat-card.total .stat-value { color: var(--accent); }
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--card);
  border-radius: 8px;
  overflow: hidden;
  font-size: 0.9rem;
}
th, td {
  padding: 12px 16px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
th { background: #252540; color: var(--accent); font-weight: 600; }
tr:hover { background: rgba(0, 212, 255, 0.05); }
.section {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 24px;
}
code {
  background: #252540;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Consolas', monospace;
  font-size: 0.85rem;
}
.badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}
.badge.block { background: rgba(255, 68, 102, 0.2); color: var(--danger); }
.badge.pass { background: rgba(0, 255, 136, 0.2); color: var(--success); }
.badge.warn { background: rgba(255, 170, 0, 0.2); color: var(--warning); }
@media (max-width: 768px) {
  body { padding: 12px; }
  header { padding: 20px; }
  .stats { grid-template-columns: 1fr 1fr; }
  .stat-value { font-size: 1.8rem; }
}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ Universal Attack Simulation Framework</h1>
    <p class="meta">
      <strong>Target:</strong> ${target}<br>
      <strong>Correlation ID:</strong> <code>${cid}</code><br>
      <strong>Generated:</strong> $(date '+%Y-%m-%d %H:%M:%S %Z')
    </p>
  </header>
  
  <div class="stats">
    <div class="stat-card total">
      <div class="stat-value">${total_requests}</div>
      <div class="stat-label">Total Requests</div>
    </div>
    <div class="stat-card block">
      <div class="stat-value">${block_count}</div>
      <div class="stat-label">Blocked</div>
    </div>
    <div class="stat-card pass">
      <div class="stat-value">${pass_count}</div>
      <div class="stat-label">Passed</div>
    </div>
    <div class="stat-card warn">
      <div class="stat-value">${block_pct}%</div>
      <div class="stat-label">Block Rate</div>
    </div>
  </div>
  
  <div class="section">
    <h2>📊 HTTP Response Codes</h2>
    <table>
      <tr><th>Code</th><th>Count</th><th>Percentage</th></tr>
      ${codes}
    </table>
  </div>
  
  <div class="section">
    <h2>🎯 Module Statistics</h2>
    <table>
      <tr><th>Module</th><th>Requests</th><th>Blocked</th><th>Block Rate</th></tr>
      ${mods}
    </table>
  </div>
  
  <div class="section">
    <h2>📋 Request Details (First 100)</h2>
    <table>
      <tr><th>Time</th><th>Module</th><th>Code</th><th>ms</th><th>Bytes</th><th>IP</th><th>URL</th><th>Verdict</th></tr>
      ${samples}
    </table>
  </div>
  
  <div class="section">
    <h2>📁 Evidence</h2>
    <p>${evidence_count} response samples saved to <code>${evidence_dir}</code></p>
  </div>
  
  <footer style="text-align:center;padding:24px;color:#666;font-size:0.85rem">
    Universal Attack Simulation Framework (UASF) • For authorized testing only
  </footer>
</div>
</body>
</html>
HTML
}
