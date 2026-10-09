from __future__ import annotations

import html
import os
import zipfile
from pathlib import Path


OUT = Path(__file__).with_name("AgentShield_Demo_Deck.pptx")
W, H = 13.333333, 7.5
NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
PNS = "http://schemas.openxmlformats.org/presentationml/2006/main"
RNS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def emu(value: float) -> int:
    return int(value * 914400)


def run(text: str, size: int, color: str = "E8F0FA", bold: bool = False, font: str = "Aptos") -> str:
    b = " b=\"1\"" if bold else ""
    return f'<a:r><a:rPr lang="en-US" sz="{size * 100}"{b}><a:solidFill><a:srgbClr val="{color}"/></a:solidFill><a:latin typeface="{font}"/></a:rPr><a:t>{esc(text)}</a:t></a:r>'


def tx(x: float, y: float, w: float, h: float, text: str, size: int = 16, color: str = "E8F0FA", bold: bool = False, align: str = "l") -> str:
    paras = "".join(f'<a:p><a:pPr algn="{align}"/><a:r><a:rPr lang="en-US" sz="{size * 100}"' + (' b="1"' if bold else '') + f'><a:solidFill><a:srgbClr val="{color}"/></a:solidFill><a:latin typeface="Aptos"/></a:rPr><a:t>{esc(line)}</a:t></a:r></a:p>' for line in text.split("\n"))
    return f'<p:sp><p:nvSpPr><p:cNvPr id="{next_id()}" name="Text"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="{emu(x)}" y="{emu(y)}"/><a:ext cx="{emu(w)}" cy="{emu(h)}"/></a:xfrm></p:spPr><p:txBody><a:bodyPr wrap="square"/><a:lstStyle/>{paras}</p:txBody></p:sp>'


_id = 1


def next_id() -> int:
    global _id
    _id += 1
    return _id


def rect(x: float, y: float, w: float, h: float, fill: str, line: str | None = None, radius: bool = False) -> str:
    ln = '<a:ln w="12000"><a:solidFill><a:srgbClr val="%s"/></a:solidFill></a:ln>' % (line or fill)
    geom = "roundRect" if radius else "rect"
    return f'<p:sp><p:nvSpPr><p:cNvPr id="{next_id()}" name="Shape"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="{emu(x)}" y="{emu(y)}"/><a:ext cx="{emu(w)}" cy="{emu(h)}"/></a:xfrm><a:prstGeom prst="{geom}"><a:avLst/></a:prstGeom><a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>{ln}</p:spPr></p:sp>'


def circle(x: float, y: float, d: float, fill: str, line: str | None = None) -> str:
    return rect(x, y, d, d, fill, line, True)


def line(x: float, y: float, w: float, color: str = "294966") -> str:
    return f'<p:sp><p:nvSpPr><p:cNvPr id="{next_id()}" name="Line"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="{emu(x)}" y="{emu(y)}"/><a:ext cx="{emu(w)}" cy="{emu(0.01)}"/></a:xfrm><a:prstGeom prst="line"><a:avLst/></a:prstGeom><a:ln w="12000"><a:solidFill><a:srgbClr val="{color}"/></a:solidFill></a:ln></p:spPr></p:sp>'


def base(slide_no: int, section: str, title: str, subtitle: str = "") -> list[str]:
    return [rect(0, 0, W, H, "07111F"), rect(0, 0, 0.18, H, "54D5B1"), tx(0.55, 0.42, 2.8, 0.3, "AGENTSHIELD  /  DEMO", 10, "62D7B1", True), tx(0.55, 0.86, 11.8, 0.58, title, 27, "F4F8FF", True), tx(0.58, 1.52, 11.5, 0.35, subtitle, 11, "8AA1B8"), tx(12.18, 0.45, 0.6, 0.25, f"0{slide_no}", 11, "6D849B", True, "r"), line(0.55, 2.05, 12.2), tx(0.55, 7.12, 8, 0.18, section.upper(), 8, "58738D", True), tx(11.4, 7.12, 1.35, 0.18, "DEFENSE IN DEPTH", 8, "58738D", True, "r")]


def slide_xml(shapes: list[str], notes: str = "") -> str:
    body = "".join(shapes)
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="{NS}" xmlns:r="{RNS}" xmlns:p="{PNS}"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>{body}</p:spTree></p:cSld><p:transition spd="med"><p:fade/></p:transition><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>'''


def make_slides() -> list[str]:
    slides: list[str] = []
    # 1
    s = [rect(0, 0, W, H, "07111F"), rect(0, 0, 0.22, H, "54D5B1"), circle(0.7, 0.8, 1.02, "12375A", "54D5B1"), tx(1.02, 1.05, 0.4, 0.3, "A+", 21, "62D7B1", True, "c"), tx(0.75, 2.05, 11.2, 0.75, "AgentShield", 42, "F5F9FF", True), tx(0.78, 2.9, 10.8, 0.75, "Runtime security firewall\nfor AI agents", 25, "B8CADB", False), rect(0.78, 4.35, 5.35, 0.62, "102A3C", "285A67", True), tx(1.02, 4.56, 4.9, 0.2, "DETECT  •  EXPLAIN  •  DECIDE  •  AUDIT", 10, "62D7B1", True), tx(0.8, 5.75, 7.0, 0.32, "Demo presentation  |  MVP security architecture", 13, "8AA1B8"), tx(8.85, 5.64, 3.55, 0.75, "Team [Name]\n[Member 1]  ·  [Member 2]  ·  [Member 3]", 12, "D6E4F1", False, "r"), tx(0.8, 6.85, 3.2, 0.18, "October 2026  ·  v0.1", 9, "58738D")]
    slides.append(slide_xml(s))
    # 2
    s = base(2, "The problem / the wedge", "From agent autonomy to accountable action", "AgentShield treats every proposed tool action as a security decision—not an assumption of trust.")
    s += [rect(0.6, 2.35, 3.8, 3.65, "0C1A2A", "1C344C", True), tx(0.9, 2.65, 3.1, 0.35, "THE GAP", 10, "ED8B8F", True), tx(0.9, 3.15, 3.1, 1.2, "Agents can be\nredirected by content", 24, "F5F8FC", True), tx(0.9, 4.75, 3.0, 0.8, "Prompt injection, secret leakage, unsafe tools, and malicious destinations are runtime problems.", 12, "8EA5B9"), rect(4.75, 2.35, 3.8, 3.65, "0E2A2A", "245B50", True), tx(5.05, 2.65, 3.1, 0.35, "OUR SOLUTION", 10, "62D7B1", True), tx(5.05, 3.15, 3.1, 1.2, "A firewall before\nthe tool call", 24, "F5F8FC", True), tx(5.05, 4.75, 3.0, 0.8, "Inspect → detect → score → enforce → record. Human approval handles the middle ground.", 12, "A1C9C3"), rect(8.9, 2.35, 3.8, 3.65, "1C1D2B", "5D4961", True), tx(9.2, 2.65, 3.1, 0.35, "WHY DIFFERENT", 10, "E8BF76", True), tx(9.2, 3.15, 3.1, 1.2, "Explainable\nby design", 24, "F5F8FC", True), tx(9.2, 4.75, 3.0, 0.8, "Deterministic rules, matched policies, factor-level risk, redacted audit evidence, and safe simulation.", 12, "C5B28D")]
    slides.append(slide_xml(s))
    # 3
    s = base(3, "Architecture", "Technical approach: a decision pipeline", "The same gateway protects registered agents, custom test actions, and deterministic demo scenarios.")
    steps = [("01", "REQUEST", "Pydantic\nvalidation"), ("02", "DETECT", "Injection +\nsensitive data"), ("03", "DECIDE", "Policy +\nrisk score"), ("04", "CONTROL", "Allow / block /\napproval / redact"), ("05", "PROVE", "SQLite +\naudit trail")]
    for i, (num, head, desc) in enumerate(steps):
        x = 0.7 + i * 2.48
        s += [circle(x, 2.55, 0.55, "12375A", "54D5B1"), tx(x, 2.7, 0.55, 0.18, num, 9, "62D7B1", True, "c"), tx(x - 0.05, 3.35, 2.1, 0.24, head, 11, "F4F8FF", True), tx(x - 0.05, 3.75, 2.1, 0.55, desc, 13, "A8BBCD"), tx(x + 1.95, 2.72, 0.35, 0.25, "→" if i < 4 else "", 18, "54D5B1", True)]
    s += [rect(0.7, 5.0, 11.75, 1.1, "0C1A2A", "1C344C", True), tx(0.98, 5.25, 11.2, 0.28, "STACK", 9, "62D7B1", True), tx(0.98, 5.62, 11.1, 0.25, "FastAPI  ·  Pydantic  ·  SQLAlchemy  ·  SQLite  ·  React  ·  TypeScript  ·  Vite  ·  Tailwind CSS  ·  Pytest  ·  Vitest", 12, "DDE8F2")]
    slides.append(slide_xml(s))
    # 4
    s = base(4, "Delivery confidence", "Feasible now. Valuable at scale.", "The MVP is deliberately simulator-first: no real shell, upload, email, or malicious-site contact is required to prove the control loop.")
    s += [rect(0.7, 2.35, 5.7, 3.75, "0C1A2A", "1C344C", True), tx(1.0, 2.7, 4.8, 0.3, "FEASIBILITY", 10, "62D7B1", True), tx(1.0, 3.2, 4.7, 0.55, "Small, typed, testable core", 22, "F5F8FF", True), tx(1.0, 4.05, 4.8, 1.35, "• Deterministic detectors and policy rules\n• SQLite persistence for the MVP\n• FastAPI gateway with strict schemas\n• Local simulator works without an LLM", 13, "A8BBCD"), rect(6.85, 2.35, 5.7, 3.75, "102A2A", "245B50", True), tx(7.15, 2.7, 4.8, 0.3, "VIABILITY", 10, "62D7B1", True), tx(7.15, 3.2, 4.7, 0.55, "A control plane, not a chatbot", 22, "F5F8FF", True), tx(7.15, 4.05, 4.8, 1.35, "• Works across agents through one gateway\n• Human approval for material risk\n• Provider-neutral monitoring surfaces\n• Migration path to stronger identity + Postgres", 13, "A1C9C3")]
    slides.append(slide_xml(s))
    # 5
    s = base(5, "Outcome", "Impact: safer autonomy with evidence", "AgentShield turns invisible failure modes into visible, reviewable decisions.")
    cards = [("01", "CONTAIN", "Block prompt injection, secret access, restricted files, and unknown destinations."), ("02", "CONTROL", "Route medium-risk actions to a human approval queue with hash-bound, single-use approvals."), ("03", "LEARN", "Use redacted traces, risk factors, and policy matches to improve agent design and governance.")]
    for i, (num, head, desc) in enumerate(cards):
        x = 0.75 + i * 4.15
        s += [rect(x, 2.45, 3.65, 2.8, "0C1A2A", "1C344C", True), tx(x + 0.28, 2.78, 0.45, 0.25, num, 11, "62D7B1", True), tx(x + 0.28, 3.28, 2.9, 0.3, head, 18, "F5F8FF", True), tx(x + 0.28, 3.9, 3.0, 0.85, desc, 12, "A8BBCD")]
    s += [rect(0.75, 5.65, 11.85, 0.55, "173D39", "2C6C5A", True), tx(1.0, 5.85, 11.3, 0.18, "NORTH STAR  /  Safe failure is better than silent autonomy.", 12, "BEE9DD", True, "c")]
    slides.append(slide_xml(s))
    # 6
    s = base(6, "Evidence", "Research & references", "A practical MVP grounded in established AI security and risk-management guidance.")
    s += [rect(0.7, 2.35, 5.8, 3.75, "0C1A2A", "1C344C", True), tx(1.0, 2.7, 5.0, 0.3, "RESEARCH BASIS", 10, "62D7B1", True), tx(1.0, 3.18, 5.0, 2.25, "• OWASP — Top 10 for LLM Applications\n• NIST — AI Risk Management Framework\n• NIST — Secure Software Development Framework\n• FastAPI + Pydantic security patterns\n• SQLite / SQLAlchemy persistence patterns\n• Internal deterministic test suite: 188 backend tests, 28 frontend tests", 12, "DDE8F2"), rect(6.8, 2.35, 5.75, 3.75, "111B2B", "2A4461", True), tx(7.1, 2.7, 5.0, 0.3, "REFERENCE LINKS", 10, "62D7B1", True), tx(7.1, 3.18, 5.0, 2.35, "owasp.org/www-project-top-10-for-large-language-model-applications\nnist.gov/itl/ai-risk-management-framework\nnist.gov/itl/ssd\nfastapi.tiangolo.com\npydantic.dev\nsqlalchemy.org", 11, "A8BBCD")]
    s += [tx(0.75, 6.55, 11.8, 0.25, "Limit: detection is defense in depth—not proof of safety or perfect security.", 12, "E8BF76", True, "c")]
    slides.append(slide_xml(s))
    return slides


def content_types() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/><Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/><Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>''' + ''.join(f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>' for i in range(1, 7)) + '</Types>'


def rels(targets: list[str]) -> str:
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + ''.join(f'<Relationship Id="rId{i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="{t}"/>' for i, t in enumerate(targets)) + '</Relationships>'


def build() -> None:
    slides = make_slides()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types())
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>')
        z.writestr("ppt/_rels/presentation.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>' + ''.join(f'<Relationship Id="rId{i+2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>' for i in range(1, 7)) + '</Relationships>')
        z.writestr("ppt/presentation.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:a="%s" xmlns:r="%s" xmlns:p="%s"><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst>%s</p:sldIdLst><p:sldSz cx="12192000" cy="6858000" type="screen16x9"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>' % (NS, RNS, PNS, ''.join(f'<p:sldId id="{255+i}" r:id="rId{i+1}"/>' for i in range(6))))
        z.writestr("ppt/slideMasters/slideMaster1.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldMaster xmlns:a="{NS}" xmlns:r="{RNS}" xmlns:p="{PNS}"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="1" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>')
        z.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/></Relationships>')
        z.writestr("ppt/slideLayouts/slideLayout1.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldLayout xmlns:a="{NS}" xmlns:r="{RNS}" xmlns:p="{PNS}" type="blank"><p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>')
        z.writestr("ppt/theme/theme1.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:theme xmlns:a="{NS}" name="AgentShield"><a:themeElements><a:clrScheme name="AgentShield"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:accent1><a:srgbClr val="54D5B1"/></a:accent1><a:accent2><a:srgbClr val="EA747E"/></a:accent2><a:accent3><a:srgbClr val="E8BF76"/></a:accent3><a:accent4><a:srgbClr val="77B9E8"/></a:accent4><a:accent5><a:srgbClr val="9E83D4"/></a:accent5><a:accent6><a:srgbClr val="F3A35C"/></a:accent6><a:hlink><a:srgbClr val="54D5B1"/></a:hlink><a:folHlink><a:srgbClr val="EA747E"/></a:folHlink></a:clrScheme><a:fontScheme name="AgentShield"><a:majorFont><a:latin typeface="Aptos Display"/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/></a:minorFont></a:fontScheme><a:fmtScheme name="AgentShield"><a:fillStyleLst/><a:lnStyleLst/><a:effectStyleLst/><a:bgFillStyleLst/></a:fmtScheme></a:themeElements></a:theme>')
        for i, slide in enumerate(slides, 1):
            z.writestr(f"ppt/slides/slide{i}.xml", slide)
            z.writestr(f"ppt/slides/_rels/slide{i}.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>')
        z.writestr("docProps/core.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>AgentShield Demo Deck</dc:title><dc:subject>Runtime security firewall for AI agents</dc:subject><dc:creator>AgentShield Team</dc:creator></cp:coreProperties>')
    print(OUT)


if __name__ == "__main__":
    build()
