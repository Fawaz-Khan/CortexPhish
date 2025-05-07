from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
import socket
import ssl
import datetime
from urllib.parse import urlparse
import traceback
import io
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

OPENROUTER_API_KEY = "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"

SUSPICIOUS_TLDS = {"gq", "ml", "tk", "cf", "ga", "xyz"}


def url_exists(url):
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return False
        socket.gethostbyname(domain)
        try:
            res = requests.head(url, timeout=5, allow_redirects=True)
            if res.status_code < 400:
                return True
        except requests.RequestException:
            pass
        res = requests.get(url, timeout=5, allow_redirects=True)
        return res.status_code < 400
    except Exception:
        return False


def check_ssl_validity(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            return expiry > datetime.datetime.utcnow()
    except:
        return False


@app.route('/explain', methods=['POST'])
def explain_red_flags():
    try:
        data = request.get_json()
        url = data.get("url", "").strip().rstrip("/")
        flags = []
        safe_signals = []
        checklist = []

        if not url:
            return jsonify({"error": "Missing URL"}), 400

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or ""

        if not domain:
            return jsonify({"error": "Invalid domain structure"}), 400

        if parsed.scheme == "https":
            safe_signals.append("Uses HTTPS")
            checklist.append("HTTPS Protocol: ✅")
        else:
            flags.append("Does not use HTTPS")
            checklist.append("HTTPS Protocol: ❌")

        if url_exists(url):
            safe_signals.append("Website is reachable")
            checklist.append("Website Reachable: ✅")
        else:
            checklist.append("Website Reachable: ❌")
            return jsonify({
                "explanation": "❌ The domain does not exist or the website is unreachable. This is a strong sign of a fake or malicious URL."
            })

        try:
            socket.inet_aton(domain)
            flags.append("Uses IP address")
            checklist.append("IP Address Used Instead of Domain: ❌")
        except:
            checklist.append("IP Address Used Instead of Domain: ✅")

        if domain.count('.') > 4:
            flags.append("Excessive subdomains")
            checklist.append("Subdomain Depth (>4): ❌")
        else:
            checklist.append("Subdomain Depth: ✅")

        if domain.count('-') >= 3:
            flags.append("Too many hyphens")
            checklist.append("Hyphen Count (>=3): ❌")
        else:
            checklist.append("Hyphen Count: ✅")

        if "xn--" in domain:
            flags.append("Punycode detected")
            checklist.append("Punycode Encoding: ❌")
        else:
            checklist.append("Punycode Encoding: ✅")

        tld = domain.split('.')[-1]
        if tld in SUSPICIOUS_TLDS:
            flags.append(f"Suspicious TLD: .{tld}")
            checklist.append(f"TLD Check (.{tld}): ❌")
        else:
            checklist.append("TLD Check: ✅")

        if len(path) > 60:
            flags.append("URL path is too long")
            checklist.append("URL Path Length (>60 chars): ❌")
        else:
            checklist.append("URL Path Length: ✅")

        if any(word in path.lower() for word in ["login", "verify", "secure", "auth"]):
            flags.append("Suspicious keywords in path")
            checklist.append("Suspicious Keywords in Path: ❌")
        else:
            checklist.append("Suspicious Keywords in Path: ✅")

        if check_ssl_validity(domain):
            safe_signals.append("Valid SSL certificate")
            checklist.append("SSL Certificate: ✅")
        else:
            flags.append("Invalid or missing SSL certificate")
            checklist.append("SSL Certificate: ❌")

        full_prompt = f"""You are a CISO. Review the following URL and display the checklist status for each check as ✅ (pass) or ❌ (fail). Keep it in this format:

Security Checklist:
{chr(10).join(checklist)}

Final Verdict: Act as a cybersecurity threat analyst. Evaluate this URL based on red flags, domain structure, semantics, and potential deception tactics. Conclude with 4 sharp, clear, and non-redundant bullet points.

Recommendation: Give suggestion to the user that is going to visit the website final bottom line. Conclude with 4 sharp, clear, and non-redundant bullet points.
"""

        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "openai/gpt-3.5-turbo",
            "messages": [{"role": "user", "content": full_prompt}],
            "temperature": 0.5
        }

        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
        result = response.json()
        explanation = result["choices"][0]["message"]["content"]

        return jsonify({"explanation": explanation})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Could not connect to AI"}), 500


class CleanPDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, "Phishing Threat Analysis Report", ln=True, align="C")
        self.ln(5)

    def add_title(self, title):
        self.set_font("Arial", "B", 12)
        self.set_text_color(180, 0, 0)
        self.cell(0, 10, title, ln=True)
        self.set_text_color(0, 0, 0)

    def add_text_block(self, text):
        self.set_font("Arial", size=11)
        self.multi_cell(0, 8, text)
        self.ln(2)


@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.get_json()
        url = data.get("url", "N/A")
        checklist = data.get("checklist", [])
        explanation = data.get("explanation", "No explanation provided.")

        pdf = CleanPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        pdf.set_font("Arial", '', 11)
        pdf.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.cell(0, 10, f"URL Analyzed: {url}", ln=True)
        pdf.ln(5)

        pdf.add_title("1. Executive Summary")
        verdict = "Suspicious Activity Detected" if any("❌" in item for item in checklist) else "No Major Red Flags"
        pdf.add_text_block(f"Verdict: {verdict}")
        pdf.add_text_block("This report provides an automated analysis of the submitted URL using static heuristics and AI-generated explanations.")

        pdf.add_title("2. Security Checklist & Definitions")
        pdf.add_text_block("HTTPS Protocol: \nDefinition: Checks if the URL uses HTTPS to protect data in transit.\n")
        pdf.add_text_block("Website Reachable: \nDefinition: Verifies if the site is online and responsive.\n")
        pdf.add_text_block("IP Address Used Instead of Domain: \nDefinition: Using raw IPs can indicate suspicious or hidden destinations.\n")
        pdf.add_text_block("Subdomain Depth: \nDefinition: Too many subdomains may attempt to trick users with layered domains.\n")
        pdf.add_text_block("Hyphen Count: \nDefinition: Excessive hyphens may mimic legitimate domain names.\n")
        pdf.add_text_block("Punycode Encoding: \nDefinition: Punycode domains may visually spoof trusted brands (e.g., xn--pple-43d.com).\n")
        pdf.add_text_block("TLD Check: \nDefinition: TLDs like .tk, .cf are often used in malicious campaigns.\n")
        pdf.add_text_block("URL Path Length: \nDefinition: Very long paths might obfuscate true intentions.\n")
        pdf.add_text_block("Suspicious Keywords in Path: \nDefinition: Words like login, secure, or auth in paths are phishing indicators.\n")
        pdf.add_text_block("SSL Certificate: \nDefinition: Checks if the domain presents a valid and current SSL certificate.\n")

        pdf.add_title("3. AI Explanation & Reasoning")
        explanation_clean = explanation.replace("✅", "[PASS]").replace("❌", "[FAIL]")
        pdf.add_text_block(explanation_clean)

        pdf.add_title("4. Legal Disclaimer")
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("Arial", "I", 9)
        disclaimer = (
            "This report is generated for educational and informational purposes only. "
            "It combines rule-based URL analysis and language model interpretation to provide phishing insights. "
            "This is not a substitute for professional cybersecurity advice. Use at your own risk."
        )
        pdf.multi_cell(0, 7, disclaimer)
        pdf.set_text_color(0, 0, 0)

        pdf_buffer = io.BytesIO()
        pdf_data = pdf.output(dest='S').encode('latin-1', 'ignore')
        pdf_buffer.write(pdf_data)
        pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name="phishing_report.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Failed to generate PDF"}), 500


if __name__ == '__main__':
    app.run(debug=True)
