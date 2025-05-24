from flask import Flask, render_template, request, send_file, session, jsonify
from scanner import scan_website, clean_url
import os
import time
import threading
from queue import Queue
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepInFrame
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

try:
    pdfmetrics.registerFont(TTFont('DejaVuSans', 'DejaVuSans.ttf'))
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'DejaVuSans-Bold.ttf'))
    FONT_NAME = 'DejaVuSans'
    FONT_NAME_BOLD = 'DejaVuSans-Bold'
except Exception as e:
    FONT_NAME = 'Helvetica'
    FONT_NAME_BOLD = 'Helvetica-Bold'

app = Flask(__name__)
app.secret_key = os.urandom(24)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

scan_queue = Queue()

def background_scan(url, scan_id):
    results = scan_website(url)
    scan_queue.put({"id": scan_id, "url": url, "results": results})

@app.route('/')
def home():
    session.pop('scan_id', None)
    session.pop('scan_url', None)
    session.pop('scan_results', None)
    session.pop('start_time', None)
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url_to_scan = request.form.get('url', '').strip()
    if not url_to_scan:
        return "Error: URL is required.", 400
    try:
        cleaned_url = clean_url(url_to_scan)
    except ValueError as e:
        return render_template('error.html', error_message=f"Invalid URL: {str(e)}", url=url_to_scan) # Show error page
    except Exception as e:
         return render_template('error.html', error_message=f"Error processing URL: {str(e)}", url=url_to_scan)


    scan_id = str(int(time.time()))
    session['scan_id'] = scan_id
    session['scan_url'] = cleaned_url
    session['start_time'] = time.time()
    session['scan_results'] = None

    thread = threading.Thread(target=background_scan, args=(cleaned_url, scan_id))
    thread.daemon = True
    thread.start()
    return render_template('progress.html', url=cleaned_url, scan_id=scan_id)

@app.route('/progress')
def progress():
    scan_id = session.get('scan_id')
    if not scan_id:
        return jsonify({"progress": 0, "status": "No scan initiated or session expired."}), 400

    if session.get('scan_results'):
        return jsonify({"progress": 100, "status": "Complete"})

    start_time = session.get('start_time', time.time())
    elapsed_time = time.time() - start_time
    fake_progress = min(95, int((elapsed_time / 45) * 100)) 

    # Check queue for this scan's results
    queue_snapshot = []
    item_found_for_this_scan = None
    while not scan_queue.empty():
        try:
            item = scan_queue.get_nowait()
            if item["id"] == scan_id:
                item_found_for_this_scan = item
            else:
                queue_snapshot.append(item)
        except Exception: # Handle Empty exception if queue becomes empty during iteration
            break
    
    # Put other items back
    for i in queue_snapshot:
        scan_queue.put(i)

    if item_found_for_this_scan:
        session['scan_results'] = item_found_for_this_scan["results"]
        session['processing_time'] = time.time() - session['start_time']
        return jsonify({"progress": 100, "status": "Complete"})
        
    return jsonify({"progress": fake_progress, "status": "Scanning..."})

@app.route('/results')
def results_page():
    if 'scan_results' not in session or not session['scan_results']:
        scan_url = session.get('scan_url', 'your target URL')
        if session.get('scan_id') and not session.get('scan_results'):
             return render_template('progress.html', url=scan_url, scan_id=session.get('scan_id'),
                                   message="Scan may still be in progress. Please wait or refresh.")
        return render_template('error.html', error_message="Scan results not found or scan not completed. Please start a new scan.")


    scan_results_data = session['scan_results']
    processing_time = session.get('processing_time', 0)
    scan_url = session.get('scan_url', 'Unknown URL')

    if "Error" in scan_results_data and len(scan_results_data) <= 2: # Check if Error is the main/only key besides Target URL
        return render_template('error.html', error_message=scan_results_data["Error"], url=scan_url)

    return render_template('results.html', url=scan_url, results=scan_results_data, processing_time=f"{processing_time:.2f}")

def generate_pdf_report(url, results_data):
    clean_filename = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    pdf_path = os.path.join(REPORTS_DIR, f"report_{clean_filename}.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                            leftMargin=0.7*inch, rightMargin=0.7*inch,
                            topMargin=0.7*inch, bottomMargin=0.7*inch)
    styles = getSampleStyleSheet()
    story = []

    style_h1 = ParagraphStyle(name='Heading1', fontName=FONT_NAME_BOLD, fontSize=18, alignment=TA_CENTER, spaceBefore=12, spaceBottom=12, textColor=colors.HexColor("#2c3e50"))
    style_h2 = ParagraphStyle(name='Heading2', fontName=FONT_NAME_BOLD, fontSize=14, spaceBefore=10, spaceBottom=6, textColor=colors.HexColor("#34495e"), borderPadding=2, leading=16)
    style_h3_url = ParagraphStyle(name='Heading3Url', fontName=FONT_NAME, fontSize=10, alignment=TA_CENTER, spaceBottom=18, textColor=colors.HexColor("#0066cc"))
    style_normal = ParagraphStyle(name='Normal_Unicode', fontName=FONT_NAME, fontSize=9, leading=12, alignment=TA_LEFT)
    style_cell_key = ParagraphStyle(name='CellKey', parent=style_normal, fontName=FONT_NAME_BOLD)
    style_cell_value = ParagraphStyle(name='CellValue', parent=style_normal) # Will allow basic HTML for emojis
    style_disclaimer = ParagraphStyle(name='Disclaimer', parent=styles['Italic'], fontName=FONT_NAME, fontSize=8, alignment=TA_CENTER, spaceBefore=20, textColor=colors.HexColor("#666666"))

    story.append(Paragraph("Vulnerability Scan Report", style_h1))

    gen_info_keys = ['Target URL', 'IP Address', 'Country', 'Region', 'City', 'Organisation', 'Geo API Error'] # Removed 'Error' to avoid general error here
    domain_info_keys = ['Domain Creation Date', 'Domain Expiration Date', 'Domain Age', 'Expiration Status', 'Status', 'WHOIS Error'] # Specific WHOIS error key

    def create_info_table(title, keys, data_source, story_list, style_heading, style_key, style_val):
        table_data = []
        for key in keys:
            original_key_to_check = key
            if key == 'WHOIS Error' and 'Error' in data_source and 'WHOIS' in str(data_source['Error']): # Check top-level error for WHOIS
                value = data_source['Error']
            else:
                 value = data_source.get(key)

            if value and value != "Unknown" and value != "Resolution Error":
                if key == 'Error' and 'WHOIS' in str(value): continue 
                if key == 'Error' and 'Geo API' in str(value): continue 
                
                table_data.append([Paragraph(original_key_to_check, style_key), Paragraph(str(value), style_val)])
        
        if table_data:
            story_list.append(Paragraph(title, style_heading))
            info_table = Table(table_data, colWidths=[2.2*inch, 4.8*inch])
            info_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('LEFTPADDING', (0,0), (-1,-1), 5), ('RIGHTPADDING', (0,0), (-1,-1), 5),
                ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor("#f0f0f0"), colors.white]),
            ]))
            story_list.append(info_table)
            story_list.append(Spacer(1, 0.15*inch))

    create_info_table("General Information", gen_info_keys, results_data, story, style_h2, style_cell_key, style_cell_value)
    create_info_table("Domain Information", domain_info_keys, results_data, story, style_h2, style_cell_key, style_cell_value)

    story.append(Paragraph("Security Check Results", style_h2))
    security_check_data_for_table = []
    exclude_keys = gen_info_keys + domain_info_keys + ['Scan Duration', 'Target URL', 'Error', 'Status'] # Exclude already handled

    security_check_items = []
    for key, value in results_data.items():
        if key in exclude_keys: continue
        security_check_items.append({'key': key, 'value': value})
    
    # Sort security checks alphabetically by key for consistent order
    security_check_items.sort(key=lambda x: x['key'])

    table_style_cmds = [
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 5), ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5), ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]
    
    row_index = 0
    for item in security_check_items:
        key, value = item['key'], item['value']
        value_str = ""
        row_color = colors.white # Default row background

        if key == 'Security Headers':
            if isinstance(value, list) and value: value_str = "<b>Present:</b> " + ", ".join(value)
            elif isinstance(value, str): value_str = value
            else: value_str = str(value) # Fallback
        elif isinstance(value, list) and value: value_str = "<b>Missing:</b> " + ", ".join(value)
        else: value_str = str(value)

        if "✅" in value_str or "Present✅" in value_str or "Safe✅" in value_str or "Good✅" in value_str: row_color = colors.HexColor("#e6ffed")
        elif "❌" in value_str or "Detected!❌" in value_str or "Vulnerable❌" in value_str or "Missing❌" in value_str or "Error❌" in value_str or "found from the predefined list.❌" in value_str: row_color = colors.HexColor("#ffeeee")
        elif "⚠️" in value_str or "Possible⚠️" in value_str or "Potential⚠️" in value_str: row_color = colors.HexColor("#fff9e6")
        
        if row_color != colors.white: # Add background style command if not default
             table_style_cmds.append(('BACKGROUND', (0, row_index), (-1, row_index), row_color))

        # Using KeepInFrame to prevent text overflow if too long, though Paragraph should wrap
        p_key = Paragraph(key, style_cell_key)
        p_value_html = value_str.replace('✅', '<font color="green"><b>✅</b></font>') \
                                .replace('❌', '<font color="red"><b>❌</b></font>') \
                                .replace('⚠️', '<font color="#FFA500"><b>⚠️</b></font>') # Orange for warning
        p_value = Paragraph(p_value_html, style_cell_value)
        
        security_check_data_for_table.append([p_key, p_value])
        row_index += 1
        
    if security_check_data_for_table:
        sec_table = Table(security_check_data_for_table, colWidths=[2.5*inch, 4.5*inch])
        sec_table.setStyle(TableStyle(table_style_cmds))
        story.append(sec_table)
    else:
        story.append(Paragraph("No security check results to display.", style_normal))

    story.append(Spacer(1, 0.15*inch))
    if results_data.get("Scan Duration"):
        story.append(Paragraph(f"<b>Scan Duration:</b> {results_data['Scan Duration']}", style_normal))

    story.append(Paragraph("<i>Disclaimer: This report is auto-generated for informational purposes. Findings should be manually verified. Professional assessment is recommended for critical systems.</i>", style_disclaimer))
    
    try:
        doc.build(story)
        return pdf_path
    except Exception as e:
        print(f"Error generating PDF for {url}: {e}")
        error_report_path = os.path.join(REPORTS_DIR, f"error_report_{clean_filename}.txt")
        with open(error_report_path, "w", encoding='utf-8') as f:
            f.write(f"Failed to generate PDF report for URL: {url}\nError: {str(e)}\n\nRaw Scan Data:\n")
            for k, v in results_data.items(): f.write(f"{k}: {v}\n")
        return error_report_path

@app.route('/download/pdf')
def download_pdf():
    scan_url = session.get('scan_url')
    results = session.get('scan_results')
    if not scan_url or not results:
        return "Scan data not found. Please perform a scan first.", 400
    if "Error" in results and len(results) <=2 : # If error is the primary result
         return render_template('error.html', error_message=f"Cannot generate report: Scan failed with error - {results['Error']}", url=scan_url)

    pdf_path = generate_pdf_report(scan_url, results)
    if pdf_path.endswith(".txt"):
        return send_file(pdf_path, as_attachment=True, download_name=os.path.basename(pdf_path), mimetype='text/plain')
    return send_file(pdf_path, as_attachment=True, download_name=os.path.basename(pdf_path))

@app.route('/download/csv')
def download_csv():
    scan_url = session.get('scan_url')
    results = session.get('scan_results', {})
    if not scan_url or not results:
        return "Scan data not found. Please perform a scan first.", 400
    if "Error" in results and len(results) <=2:
         return render_template('error.html', error_message=f"Cannot generate report: Scan failed with error - {results['Error']}", url=scan_url)

    clean_filename = scan_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    csv_path = os.path.join(REPORTS_DIR, f"report_{clean_filename}.csv")
    csv_data = []

    # Define order for CSV to be somewhat consistent with PDF/HTML
    ordered_keys = [
        'Target URL', 'IP Address', 'Country', 'Region', 'City', 'Organisation', 'Geo API Error',
        'Domain Creation Date', 'Domain Expiration Date', 'Domain Age', 'Expiration Status', 'Status', 'WHOIS Error', # 'Error' might be generic
        # Security Checks will be added from remaining items
    ]
    # Add security check keys (sorted)
    sec_check_keys = sorted([k for k in results.keys() if k not in ordered_keys and k not in ['Scan Duration', 'Error']]) # Exclude generic error
    ordered_keys.extend(sec_check_keys)
    ordered_keys.append('Scan Duration')
    if 'Error' in results and 'Error' not in ordered_keys: # Add general error if not covered
        ordered_keys.append('Error')


    for key in ordered_keys:
        if key in results:
            value = results[key]
            if isinstance(value, list):
                if key == 'Security Headers':
                    csv_data.append([key, "Present: " + (", ".join(str(v) for v in value) if value else "None from target list")])
                else: # Assume other lists are "missing"
                    csv_data.append([key, "Missing: " + (", ".join(str(v) for v in value) if value else "None")])
            else:
                csv_data.append([key, str(value) if value is not None else "N/A"])
            
    df = pd.DataFrame(csv_data, columns=["Check", "Result"])
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True, download_name=os.path.basename(csv_path))

if __name__ == '__main__':
    app.run(debug=True, threaded=True)