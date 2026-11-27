
import json
import html
from collections import Counter
from pathlib import Path
from datetime import datetime

# 输入和输出文件
BASE_DIR = Path(__file__).parent
INPUT_FILE = BASE_DIR / "sbom-report.json"
OUTPUT_FILE = BASE_DIR / "sbom-report.html"


def get_license(component):
    licenses = component.get("licenses", [])
    result = []

    for item in licenses:
        license_info = item.get("license", {})
        name = license_info.get("name") or license_info.get("id")

        if name:
            result.append(name)

    return ", ".join(result) if result else "未提供"


def safe(value):
    return html.escape(str(value or ""))


def main():
    if not INPUT_FILE.exists():
        print(f"找不到文件：{INPUT_FILE}")
        return

    with INPUT_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)

    components = data.get("components", [])

    license_counter = Counter(
        license_name
        for component in components
        for license_name in [get_license(component)]
        if license_name != "未提供"
    )

    component_rows = []

    for component in components:
        name = safe(component.get("name", "未知"))
        version = safe(component.get("version", "未知"))
        component_type = safe(component.get("type", "未知"))
        purl = safe(component.get("purl", ""))
        licenses = safe(get_license(component))

        component_rows.append(f"""
        <tr>
            <td>{name}</td>
            <td>{version}</td>
            <td>{component_type}</td>
            <td>{licenses}</td>
            <td class="purl">{purl}</td>
        </tr>
        """)

    license_rows = "".join(
        f"<tr><td>{safe(name)}</td><td>{count}</td></tr>"
        for name, count in license_counter.most_common()
    )

    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SBOM 软件物料清单报告</title>
<style>
body {{
    font-family: "Microsoft YaHei", Arial, sans-serif;
    background: #f4f6fa;
    margin: 0;
    padding: 30px;
    color: #263445;
}}
.container {{
    max-width: 1400px;
    margin: auto;
}}
.header {{
    background: #ffffff;
    padding: 25px;
    border-radius: 10px;
    margin-bottom: 20px;
}}
.header h1 {{ margin: 0 0 10px; }}
.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 18px;
    margin-bottom: 20px;
}}
.card {{
    background: white;
    padding: 24px;
    border-radius: 10px;
}}
.number {{
    font-size: 30px;
    font-weight: bold;
    color: #2563eb;
}}
.section {{
    background: white;
    padding: 22px;
    border-radius: 10px;
    margin-bottom: 20px;
    overflow-x: auto;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 750px;
}}
th, td {{
    padding: 12px;
    border-bottom: 1px solid #e8edf3;
    text-align: left;
}}
th {{ background: #f1f5f9; }}
tr:hover {{ background: #f8fafc; }}
input {{
    width: 300px;
    max-width: 90%;
    padding: 10px;
    margin: 12px 0;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
}}
.purl {{
    overflow-wrap: anywhere;
    max-width: 350px;
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>SBOM 软件物料清单报告</h1>
    <p>扫描工具：Syft</p>
    <p>报告格式：CycloneDX JSON</p>
    <p>生成时间：{generated_time}</p>
</div>

<div class="cards">
    <div class="card">
        <div class="number">{len(components)}</div>
        <div>组件总数</div>
    </div>
    <div class="card">
        <div class="number">{len(license_counter)}</div>
        <div>已识别许可证类型</div>
    </div>
    <div class="card">
        <div class="number">{sum(1 for c in components if c.get('version'))}</div>
        <div>已识别版本的组件</div>
    </div>
</div>

<div class="section">
    <h2>组件明细</h2>
    <input type="text" id="search" placeholder="搜索组件名称、版本、许可证..."
           onkeyup="filterTable()">
    <table id="componentTable">
        <thead>
            <tr>
                <th>组件名称</th>
                <th>版本</th>
                <th>类型</th>
                <th>许可证</th>
                <th>PURL</th>
            </tr>
        </thead>
        <tbody>
            {''.join(component_rows)}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>许可证统计</h2>
    <table>
        <thead>
            <tr><th>许可证</th><th>组件数量</th></tr>
        </thead>
        <tbody>
            {license_rows}
        </tbody>
    </table>
</div>

</div>

<script>
function filterTable() {{
    const keyword = document.getElementById("search").value.toLowerCase();
    const rows = document.querySelectorAll("#componentTable tbody tr");

    rows.forEach(row => {{
        row.style.display = row.innerText.toLowerCase().includes(keyword)
            ? "" : "none";
    }});
}}
</script>

</body>
</html>
"""

    OUTPUT_FILE.write_text(report, encoding="utf-8")

    print("HTML 报告生成成功！")
    print(f"报告位置：{OUTPUT_FILE}")


if __name__ == "__main__":
    main()
