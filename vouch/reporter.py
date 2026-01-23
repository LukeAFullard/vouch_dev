import os
import json
import zipfile
import tempfile
import html
import datetime

class Reporter:
    @staticmethod
    def generate_report(vch_path, output_path, format="html"):
        if not os.path.exists(vch_path):
            raise FileNotFoundError(f"File not found: {vch_path}")

        if format not in ["html", "md"]:
            raise ValueError("Invalid format. Must be 'html' or 'md'")

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                with zipfile.ZipFile(vch_path, 'r') as z:
                    # Safe extraction (Zip Slip protection)
                    for member in z.infolist():
                        name = member.filename
                        if name.startswith('/') or '..' in name:
                            continue

                        target_path = os.path.join(temp_dir, name)
                        try:
                            if os.path.commonpath([os.path.abspath(target_path), os.path.abspath(temp_dir)]) != os.path.abspath(temp_dir):
                                continue
                        except ValueError:
                            continue

                        z.extract(member, temp_dir)
            except zipfile.BadZipFile:
                raise ValueError("Invalid Vouch file (not a zip)")

            # Load Data
            log_path = os.path.join(temp_dir, "audit_log.json")
            env_path = os.path.join(temp_dir, "environment.lock")
            artifacts_path = os.path.join(temp_dir, "artifacts.json")

            audit_log = []
            if os.path.exists(log_path):
                audit_log = Reporter._read_logs(log_path)

            env_info = {}
            if os.path.exists(env_path):
                with open(env_path, 'r') as f:
                    env_info = json.load(f)

            artifacts = {}
            if os.path.exists(artifacts_path):
                with open(artifacts_path, 'r') as f:
                    artifacts = json.load(f)

            # Generate Output
            if format == "html":
                content = Reporter._render_html(vch_path, audit_log, env_info, artifacts)
            else:
                content = Reporter._render_md(vch_path, audit_log, env_info, artifacts)

            with open(output_path, 'w') as f:
                f.write(content)

            return True

    @staticmethod
    def _read_logs(path):
        try:
            with open(path, 'r') as f:
                first = f.read(1)

            with open(path, 'r') as f:
                if first == '[':
                    return json.load(f)
                else:
                    return [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading log {path}: {e}")
            return []

    @staticmethod
    def _render_html(filename, log, env, artifacts):
        # Calculate summary stats
        start_time = log[0]['timestamp'] if log else "N/A"
        end_time = log[-1]['timestamp'] if log else "N/A"
        total_calls = len(log)

        # Safe getters
        python_ver = env.get('python_version', 'Unknown')
        platform = env.get('platform', 'Unknown')
        gpu_info = env.get('gpu_info', 'N/A')

        rows = []
        for entry in log:
            seq = entry.get('sequence_number', '-')
            ts = entry.get('timestamp', '')
            target = html.escape(entry.get('target', ''))
            args = html.escape(str(entry.get('args_repr', [])))
            kwargs = html.escape(str(entry.get('kwargs_repr', {})))
            result = html.escape(str(entry.get('result_repr', '')))

            rows.append(f"""
            <tr>
                <td>{seq}</td>
                <td>{ts}</td>
                <td>{target}</td>
                <td><pre>{args}</pre></td>
                <td><pre>{kwargs}</pre></td>
                <td><pre>{result}</pre></td>
            </tr>
            """)

        artifact_rows = []
        for name, hash_val in artifacts.items():
            artifact_rows.append(f"<li><strong>{html.escape(name)}</strong>: <code>{hash_val}</code></li>")

        artifact_html = "<ul>" + "".join(artifact_rows) + "</ul>" if artifact_rows else "<p>No artifacts bundled.</p>"

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch Audit Report: {os.path.basename(filename)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .meta-item label {{ display: block; font-weight: bold; color: #666; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; vertical-align: top; }}
        th {{ background-color: #f1f1f1; font-weight: 600; }}
        tr:hover {{ background-color: #f9f9f9; }}
        pre {{ margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.85em; background: #eee; padding: 4px; border-radius: 4px; }}
        code {{ background: #eee; padding: 2px 4px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>Vouch Audit Report</h1>

    <div class="summary">
        <h2>Session Summary</h2>
        <div class="meta-grid">
            <div class="meta-item"><label>File</label>{os.path.basename(filename)}</div>
            <div class="meta-item"><label>Start Time</label>{start_time}</div>
            <div class="meta-item"><label>End Time</label>{end_time}</div>
            <div class="meta-item"><label>Total Operations</label>{total_calls}</div>
        </div>
    </div>

    <div class="summary">
        <h2>Environment</h2>
        <div class="meta-grid">
            <div class="meta-item"><label>Python Version</label>{python_ver}</div>
            <div class="meta-item"><label>Platform</label>{platform}</div>
            <div class="meta-item"><label>GPU</label>{gpu_info}</div>
        </div>
    </div>

    <h2>Artifacts</h2>
    {artifact_html}

    <h2>Audit Log</h2>
    <table>
        <thead>
            <tr>
                <th width="50">Seq</th>
                <th width="180">Timestamp</th>
                <th width="150">Action/Target</th>
                <th>Args</th>
                <th>Kwargs</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>

    <p style="text-align: center; margin-top: 50px; color: #888; font-size: 0.8em;">Generated by Vouch Reporter</p>
</body>
</html>
        """

    @staticmethod
    def _render_md(filename, log, env, artifacts):
        # Calculate summary stats
        start_time = log[0]['timestamp'] if log else "N/A"
        end_time = log[-1]['timestamp'] if log else "N/A"
        total_calls = len(log)

        # Safe getters
        python_ver = env.get('python_version', 'Unknown')
        platform = env.get('platform', 'Unknown')
        gpu_info = env.get('gpu_info', 'N/A')

        lines = []
        lines.append(f"# Vouch Audit Report")
        lines.append(f"**File:** `{os.path.basename(filename)}`\n")

        lines.append("## Session Summary")
        lines.append(f"- **Start Time:** {start_time}")
        lines.append(f"- **End Time:** {end_time}")
        lines.append(f"- **Total Operations:** {total_calls}")
        lines.append("")

        lines.append("## Environment")
        lines.append(f"- **Python Version:** `{python_ver}`")
        lines.append(f"- **Platform:** `{platform}`")
        lines.append(f"- **GPU:** `{gpu_info}`")
        lines.append("")

        lines.append("## Artifacts")
        if artifacts:
            for name, hash_val in artifacts.items():
                lines.append(f"- **{name}**: `{hash_val}`")
        else:
            lines.append("No artifacts bundled.")
        lines.append("")

        lines.append("## Audit Log")

        for entry in log:
            seq = entry.get('sequence_number', '-')
            ts = entry.get('timestamp', '')
            target = entry.get('target', '')
            args = str(entry.get('args_repr', []))
            kwargs = str(entry.get('kwargs_repr', {}))
            result = str(entry.get('result_repr', ''))

            lines.append(f"### {seq}. {target}")
            lines.append(f"- **Timestamp:** {ts}")
            lines.append(f"- **Args:** `{args}`")
            lines.append(f"- **Kwargs:** `{kwargs}`")
            lines.append(f"- **Result:** `{result}`")
            lines.append("")

        return "\n".join(lines)
