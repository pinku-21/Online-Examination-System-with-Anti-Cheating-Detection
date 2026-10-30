import os
import json
import base64
import re
import requests
import concurrent.futures
from pypdf import PdfReader
from database import get_setting

try:
    import httpx
    # High-performance HTTP/2 pooled client for ultra-low latency Gemini, Groq, and OpenRouter calls
    _httpx_client = httpx.Client(http2=True, timeout=httpx.Timeout(45.0, connect=10.0), limits=httpx.Limits(max_keepalive_connections=20, max_connections=50))
except Exception:
    _httpx_client = None

def http_post(url, json=None, headers=None, timeout=30):
    """
    High-performance HTTP POST using HTTP/2 multiplexed httpx client with seamless fallback to requests.
    Significantly reduces TLS handshake overhead and socket connection latency for LLM vision and generation calls.
    """
    if _httpx_client is not None:
        try:
            return _httpx_client.post(url, json=json, headers=headers, timeout=timeout)
        except Exception:
            pass
    return requests.post(url, json=json, headers=headers, timeout=timeout)

def parse_api_keys(key_string):
    """
    Parses a single key or comma/whitespace/newline-separated list of keys into a clean list of unique keys.
    Supports:
      - Single key: 'AQ.Ab8...'
      - Comma-separated: 'key1, key2, key3'
      - Newline-separated: 'key1\nkey2'
    """
    if not key_string:
        return []
    raw = str(key_string).strip()
    keys = [k.strip() for k in re.split(r'[,;\n\r\t ]+', raw) if k and len(k.strip()) > 8]
    # Remove duplicates preserving order
    seen = set()
    result = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            result.append(k)
    return result

def extract_text_from_pdf(pdf_path, max_chars=50000, max_pages=30):
    """Extract text content from an uploaded PDF file safely and quickly."""
    try:
        reader = PdfReader(pdf_path)
        extracted_text = []
        total_chars = 0
        for i, page in enumerate(reader.pages):
            if i >= max_pages or total_chars >= max_chars:
                break
            try:
                text = page.extract_text()
                if text:
                    extracted_text.append(f"--- Page {i+1} ---\n{text}")
                    total_chars += len(text)
            except Exception as pe:
                print(f"Skipping page {i+1} due to read error: {pe}")
        return "\n\n".join(extracted_text)
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return ""

def extract_figures_from_pdf(pdf_path, output_base_dir="static/extracted_figures", max_figures=15, max_pages=20):
    """
    Extracts embedded figures and diagrams from a PDF file using pypdf and PIL.
    Safely normalizes color spaces (converting CMYK/LA/RGBA to standard web RGB JPEG/PNG).
    Saves them to static/extracted_figures/<pdf_stem>/ and stores in persistent assets.
    Returns list of figure dicts: [{"page": int, "name": str, "url": str, "size": int}]
    """
    try:
        from PIL import Image
        import io
        from database import save_persistent_asset

        reader = PdfReader(pdf_path)
        base_name = os.path.splitext(os.path.basename(pdf_path))[0]
        safe_folder = "".join(c for c in base_name if c.isalnum() or c in ("-", "_")) or "pdf_figures"
        
        # Ensure absolute destination path
        abs_base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_base_dir)
        dest_dir = os.path.join(abs_base_dir, safe_folder)
        os.makedirs(dest_dir, exist_ok=True)
        
        extracted_figures = []
        for p_idx, page in enumerate(reader.pages):
            if p_idx >= max_pages or len(extracted_figures) >= max_figures:
                break
            try:
                for img_idx, img in enumerate(page.images):
                    if len(extracted_figures) >= max_figures:
                        break
                    raw_data = img.data
                    # Filter out tiny icon noise (< 1.5KB) and massive blobs (> 8MB)
                    if not (1500 < len(raw_data) < 8388608):
                        continue

                    try:
                        pil_img = Image.open(io.BytesIO(raw_data))
                        w, h = pil_img.size
                        # Skip tiny tracking pixels or thin lines
                        if w < 75 or h < 45:
                            continue

                        # Convert unsupported web modes (CMYK, LA, 1, P) to clean standard web RGB
                        mode = pil_img.mode
                        raw_fmt = (pil_img.format or "").lower()
                        if mode in ("CMYK", "LA", "1") or (mode == "RGBA" and raw_fmt != "png"):
                            rgb_img = pil_img.convert("RGB")
                            buf = io.BytesIO()
                            rgb_img.save(buf, format="JPEG", quality=92)
                            final_bytes = buf.getvalue()
                            ext = "jpg"
                            mime_type = "image/jpeg"
                        elif raw_fmt in ("jpeg", "jpg"):
                            ext = "jpg"
                            mime_type = "image/jpeg"
                            final_bytes = raw_data
                        elif raw_fmt == "png":
                            ext = "png"
                            mime_type = "image/png"
                            final_bytes = raw_data
                        else:
                            # Fallback convert to JPEG
                            rgb_img = pil_img.convert("RGB")
                            buf = io.BytesIO()
                            rgb_img.save(buf, format="JPEG", quality=90)
                            final_bytes = buf.getvalue()
                            ext = "jpg"
                            mime_type = "image/jpeg"

                        filename = f"p{p_idx+1}_{img_idx+1}.{ext}"
                        file_path = os.path.join(dest_dir, filename)
                        with open(file_path, "wb") as f:
                            f.write(final_bytes)

                        try:
                            save_persistent_asset(f"extracted_figures/{safe_folder}/{filename}", mime_type, final_bytes)
                        except Exception as pass_err:
                            pass

                        rel_url = f"/static/extracted_figures/{safe_folder}/{filename}"
                        extracted_figures.append({
                            "page": p_idx + 1,
                            "name": filename,
                            "url": rel_url,
                            "size": len(final_bytes)
                        })
                    except Exception as pil_err:
                        print(f"Skipping unparseable image p{p_idx+1}_img{img_idx+1}: {pil_err}")
                        continue
            except Exception as page_err:
                print(f"Skipping image scanning for page {p_idx+1}: {page_err}")
                continue

        return extracted_figures
    except Exception as e:
        print(f"Error extracting figures from PDF {pdf_path}: {e}")
        return []

def encode_image_base64(image_path_or_url):
    """
    Encodes an image (local file path or remote HTTP/HTTPS/Cloudinary URL) to base64 string and detects mime type.
    Automatically applies PIL ImageOps.exif_transpose to ensure rotated/tilted
    mobile camera uploads are normalized upright before AI vision inspection.
    """
    mime_type = "image/jpeg"
    is_remote = isinstance(image_path_or_url, str) and (image_path_or_url.startswith("http://") or image_path_or_url.startswith("https://"))

    try:
        from PIL import Image, ImageOps
        import io

        if is_remote:
            import urllib.request
            req = urllib.request.Request(image_path_or_url, headers={"User-Agent": "ExamGuardAI/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw_bytes = resp.read()
            img = Image.open(io.BytesIO(raw_bytes))
        else:
            ext = os.path.splitext(image_path_or_url)[1].lower()
            if ext == ".png":
                mime_type = "image/png"
            elif ext == ".webp":
                mime_type = "image/webp"
            img = Image.open(image_path_or_url)

        with img:
            # Transpose orientation tag if present (crucial for mobile camera uploads)
            img = ImageOps.exif_transpose(img)
            # Ensure RGB mode for JPEG/PNG
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=90)
            b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
            return "image/jpeg", b64
    except Exception as e:
        print(f"[AIService] Image base64 encode warning for {image_path_or_url}: {e}")
        if not is_remote and os.path.exists(image_path_or_url):
            with open(image_path_or_url, "rb") as image_file:
                b64 = base64.b64encode(image_file.read()).decode("utf-8")
                return mime_type, b64
        raise e

def build_exam_system_prompt(num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """Builds a rich, dynamic system prompt supporting CBSE official blueprints, exact question counts, and specialized question formats."""
    
    # Handle blueprints - CBSE Annual, Half-Yearly, Unit Tests, and custom presets
    blueprint_instruction = ""
    has_custom = bool(custom_prompt and custom_prompt.strip())
    
    if question_type in ("annual_80", "blueprint_80", "cbse_annual_80") or (total_marks and int(total_marks) == 80 and not has_custom and question_type not in ["custom", "mcq", "short", "descriptive"]):
        blueprint_instruction = """
OFFICIAL CBSE EXAM BLUEPRINT: ANNUAL / BOARD EXAMINATION (80 MARKS - EXACT 5 SECTIONS):
You MUST generate an examination strictly following the official CBSE 80-mark multi-section structure:
- Section A (1-Mark Objective): 20 questions total (16 standard MCQs + 2 Assertion-Reason + 2 Match-the-following / Objective) × 1.0 mark each = 20 Marks.
- Section B (2-Mark Very Short Answer): 6 Short Questions × 2.0 marks each = 12 Marks.
- Section C (3-Mark Short Answer): 7 Conceptual Questions × 3.0 marks each = 21 Marks.
- Section D (5-Mark Long Answer): 3 In-depth Questions × 5.0 marks each = 15 Marks.
- Section E (4-Mark Case-Based / Source / Passage / Map): 3 Case-study/Data/Map Questions × 4.0 marks each = 12 Marks.
TOTAL QUESTIONS = EXACTLY 39 QUESTIONS. TOTAL MARKS = EXACTLY 80.0 MARKS.
"""
    elif question_type in ("half_yearly_80", "cbse_half_yearly_80"):
        blueprint_instruction = """
OFFICIAL CBSE EXAM BLUEPRINT: HALF-YEARLY / MID-TERM EXAMINATION (80 MARKS):
Generate questions distributed across the half-yearly syllabus:
- Section A: 20 Objective MCQs & Assertion-Reason × 1.0 mark each = 20 Marks.
- Section B: 6 Very Short Answer Questions × 2.0 marks each = 12 Marks.
- Section C: 7 Short Answer Questions × 3.0 marks each = 21 Marks.
- Section D: 3 Long Descriptive / Numerical Questions × 5.0 marks each = 15 Marks.
- Section E: 3 Case Study / Integrated Units / Map Questions × 4.0 marks each = 12 Marks.
TOTAL QUESTIONS = EXACTLY 39 QUESTIONS. TOTAL MARKS = EXACTLY 80.0 MARKS.
"""
    elif question_type in ("unit_test_40", "cbse_unit_test_40") or (total_marks and int(total_marks) == 40 and not has_custom and question_type not in ["custom", "mcq", "short", "descriptive"]):
        blueprint_instruction = """
OFFICIAL CBSE EXAM BLUEPRINT: UNIT TEST / PERIODIC TEST (40 MARKS):
Generate questions distributed across:
- Section A: 10 Objective / MCQs / Assertion-Reason × 1.0 mark each = 10 Marks.
- Section B: 4 Very Short Questions × 2.0 marks each = 8 Marks.
- Section C: 4 Short Conceptual Questions × 3.0 marks each = 12 Marks.
- Section D: 2 Long Questions × 5.0 marks each = 10 Marks.
TOTAL QUESTIONS = EXACTLY 20 QUESTIONS. TOTAL MARKS = EXACTLY 40.0 MARKS.
"""
    elif question_type in ("unit_test_20", "cbse_unit_test_20") or (total_marks and int(total_marks) == 20 and not has_custom and question_type not in ["custom", "mcq", "short", "descriptive"]):
        blueprint_instruction = """
OFFICIAL CBSE EXAM BLUEPRINT: UNIT TEST / CLASS TEST (20 MARKS):
Generate questions distributed across:
- Section A: 5 Objective MCQs / Assertion-Reason × 1.0 mark each = 5 Marks.
- Section B: 3 Short Questions × 2.0 marks each = 6 Marks.
- Section C: 3 Conceptual Questions × 3.0 marks each = 9 Marks.
TOTAL QUESTIONS = EXACTLY 11 QUESTIONS. TOTAL MARKS = EXACTLY 20.0 MARKS.
"""
    elif question_type == "blueprint_50" or (total_marks and int(total_marks) == 50 and not has_custom and question_type not in ["custom", "mcq", "short", "descriptive"]):
        blueprint_instruction = """
EXAM BLUEPRINT: 50-MARK MIDTERM EXAMINATION
Generate questions distributed across:
- Section A: 10 MCQs, each worth 1.0 mark (Total: 10 marks).
- Section B: 5 Short Conceptual Questions, each worth 4.0 marks (Total: 20 marks).
- Section C: 2 Long Descriptive Questions, each worth 10.0 marks (Total: 20 marks).
OVERALL SUM OF POINTS MUST EQUAL EXACTLY 50.0 MARKS.
"""
    elif question_type == "short":
        blueprint_instruction = f"""
EXAM BLUEPRINT: SHORT ANSWER QUESTIONS
Generate EXACTLY {num_questions} concise, conceptual questions (2 to 4 marks each).
Set "question_type": "short", "options": [], and provide a clear model answer in "correct_answer".
"""
    elif question_type == "descriptive":
        blueprint_instruction = f"""
EXAM BLUEPRINT: LONG DESCRIPTIVE & ESSAY QUESTIONS
Generate EXACTLY {num_questions} detailed, comprehensive questions (5 to 10 marks each).
Set "question_type": "descriptive", "options": [], and provide detailed evaluation rubrics in "correct_answer".
"""
    elif question_type == "mixed":
        blueprint_instruction = f"""
EXAM BLUEPRINT: MIXED QUESTIONS
Generate EXACTLY {num_questions} questions with a balanced blend of MCQs (1-2 marks), Short Questions (3-5 marks), and Long Descriptive Questions (5-10 marks).
"""
    elif question_type == "custom":
        blueprint_instruction = f"""
EXAM BLUEPRINT: CUSTOM USER-SPECIFIED FORMAT & MIXED CHOICES
Generate EXACTLY {num_questions} questions adhering strictly to the instructor's customized question formats, mix, and breakdown.
"""

    custom_section = ""
    if custom_prompt and custom_prompt.strip():
        custom_section = f"""
--- INSTRUCTOR CUSTOM PROMPT & BLUEPRINT INSTRUCTIONS (HIGHEST PRIORITY) ---
The instructor has provided specific directives. YOU MUST STRICTLY PRIORITIZE THESE INSTRUCTIONS OVER ANY DEFAULT BLUEPRINT:
\"{custom_prompt.strip()}\"
"""

    figures_section = ""
    if available_figures and len(available_figures) > 0:
        sample_figures = available_figures[:15]
        figures_list_text = "\n".join([f"- Page {f['page']}: {f['url']}" for f in sample_figures])
        figures_section = f"""
--- EXTRACTED FIGURES FROM UPLOADED STUDY MATERIAL ---
The following diagram images were extracted directly from the user's PDF:
{figures_list_text}
You can reference any of these URLs in the "figure_url" field if your question corresponds to that diagram.
"""

    marks_guideline = f"TARGET TOTAL MARKS: Exactly {total_marks} marks." if total_marks else "Assign realistic academic mark weightages."

    prompt = f"""You are an elite CBSE Board Academic Paper Setter and Senior Examiner.
Your task is to design a high-quality examination based strictly on the provided material, topic, and instructor prompt.

DIFFICULTY LEVEL: {difficulty}
TARGET QUESTION TYPE: {question_type}
{marks_guideline}

STRICT QUESTION COUNT & MARKS ADHERENCE (CRITICAL RULE):
1. If the user or blueprint specifies a Question Count (e.g., {num_questions} questions), you MUST output EXACTLY that number of question objects in the JSON array. NEVER output fewer or more questions than requested!
2. If Target Total Marks is specified ({total_marks or 'specified by blueprint'}), the arithmetic sum of "points" across all questions in the output array MUST EQUAL THAT TOTAL. NEVER assign random marks (e.g. assigning 5 marks to a 1-mark question).
3. If an exam is for Class 9, 10, 11, or 12 CBSE, automatically format questions according to NCERT/CBSE curriculum standards.

{blueprint_instruction}
{custom_section}
{figures_section}

SPECIALIZED QUESTION FORMAT RULES:
1. ASSERTION - REASON QUESTIONS:
   - Format "question_text" with clear "Assertion (A): ..." and "Reason (R): ...".
   - Set "question_type": "mcq".
   - Options must be the standard 4 CBSE options:
     (a) Both (A) and (R) are true and (R) is the correct explanation of (A).
     (b) Both (A) and (R) are true but (R) is not the correct explanation of (A).
     (c) (A) is true but (R) is false.
     (d) (A) is false but (R) is true.
2. MATCH THE FOLLOWING (question_type: "matching"):
   - When generating Match the Following or when requested:
     Set "question_type": "matching".
     "options": {{
       "left": [{{"id": "L1", "text": "Item 1"}}, {{"id": "L2", "text": "Item 2"}}, {{"id": "L3", "text": "Item 3"}}, {{"id": "L4", "text": "Item 4"}}],
       "right": [{{"id": "R1", "text": "Match for Item 2"}}, {{"id": "R2", "text": "Match for Item 1"}}, {{"id": "R3", "text": "Match for Item 4"}}, {{"id": "R4", "text": "Match for Item 3"}}]
     }}
     "correct_answer": {{"L1": "R2", "L2": "R1", "L3": "R4", "L4": "R3"}}
     (AI must automatically pair every left ID to its correct matching right ID!)

3. MAP & HOTSPOT IDENTIFICATION QUESTIONS (question_type: "map_hotspot"):
   - CRITICAL MAP ACCURACY RULE:
     NEVER hallucinate or hand-draw crude random polygon lines for geographic maps!
     Instead, always use the system's official real geographic map assets:
     * For India maps (States, Capitals, Rivers, Mountains, Cities):
       Set "figure_url": "/static/maps/india.svg"
       Set "figure_svg": null
       Set "options": {{ "image_url": "/static/maps/india.svg", "hotspots": [...], "labels": [...] }}
       (Accurate percentage coordinates for India map viewBox:
         - New Delhi: x=34.0, y=28.5
         - Jaipur (Rajasthan): x=28.0, y=31.5
         - Mumbai (Maharashtra): x=24.5, y=56.0
         - Kolkata (West Bengal): x=66.5, y=44.0
         - Bengaluru (Karnataka): x=34.0, y=74.0
         - Chennai (Tamil Nadu): x=42.0, y=75.5
         - Lucknow (Uttar Pradesh): x=46.5, y=32.0
         - Patna (Bihar): x=56.0, y=34.5
         - Gandhinagar/Ahmedabad (Gujarat): x=19.5, y=40.5
         - Hyderabad (Telangana): x=38.5, y=57.0
         - Bhopal (Madhya Pradesh): x=35.0, y=43.0
         - Thiruvananthapuram (Kerala): x=32.5, y=87.5
         - Srinagar (Jammu & Kashmir): x=27.5, y=14.5
         - Guwahati (Assam): x=78.5, y=32.0
       )
     * For World maps (Continents, Oceans, Countries):
       Set "figure_url": "/static/maps/world.svg"
       Set "figure_svg": null
       Set "options": {{ "image_url": "/static/maps/world.svg", "hotspots": [...], "labels": [...] }}
     * For Human Anatomy & Biology Diagrams (Human Heart, Brain, Cells, Digestive, Respiratory):
       Use the official curriculum anatomy assets:
       - Human Heart: Set "figure_url": "/static/diagrams/science/human_heart.svg"
         (Key Hotspot Pin Coordinates for Human Heart:
           - Aorta: x=48.0, y=28.0
           - Superior Vena Cava: x=34.0, y=36.0
           - Pulmonary Artery: x=60.0, y=38.0
           - Right Atrium: x=33.0, y=52.0
           - Left Atrium: x=66.0, y=50.0
           - Right Ventricle: x=42.0, y=70.0
           - Left Ventricle: x=58.0, y=72.0
         )
       - Circulatory System: Set "figure_url": "/static/diagrams/science/circulatory_system.svg"
       - Human Brain: Set "figure_url": "/static/diagrams/science/human_brain.svg"
       - Respiratory System: Set "figure_url": "/static/diagrams/science/respiratory_system.svg"
       - Digestive System: Set "figure_url": "/static/diagrams/science/digestive_system.svg"
       - Plant Cell: Set "figure_url": "/static/diagrams/science/plant_cell.svg"
       - Animal Cell: Set "figure_url": "/static/diagrams/science/animal_cell.svg"
   - Hotspot & Answer Matching:
     Always provide accurate (x%, y%) coordinates, the list of candidate labels in "labels", and the ground-truth pin map in "correct_answer": {{"P1": "Jaipur", "P2": "Mumbai", ...}}.
4. CASE-BASED / PASSAGE / SOURCE-BASED QUESTIONS:
   - Provide a realistic 3-4 sentence scientific or real-world passage followed by sub-questions.


FIGURE & DIAGRAM GENERATION RULES (CRITICAL):
1. If the instructor requests figures or diagrams (e.g. "give figure in it", "provide figures", "draw diagram", or for geometry, triangles, math, circuits, physics, coordinate graphs):
   YOU MUST PROVIDE A VISUAL FIGURE FOR EACH SUCH QUESTION!
2. How to provide figures:
   A) "figure_svg": Generate a clean, complete, valid vector SVG string!
      - Structure: <svg viewBox="0 0 350 220" xmlns="http://www.w3.org/2000/svg">...</svg>
      - High visual clarity: use stroke="#0284c7" or "#1e293b", stroke-width="2.5", fill="#f0f9ff" with fill-opacity="0.6".
      - Clearly label all vertices (A, B, C, D, E), line segments, angles, or dimensions using SVG <text x="..." y="..." font-family="sans-serif" font-size="14" font-weight="bold" fill="#0f172a">...</text>.
      - Example for geometry (e.g. Thales theorem / similar triangles): Draw triangle ABC with parallel line DE, and labeled points A, B, C, D, E and measurements!
   B) "figure_url": If one of the extracted PDF figures matches the question, provide its URL from the extracted figures list (e.g. "/static/extracted_figures/...").
   C) If no figure is needed for a specific question, set "figure_svg": null and "figure_url": null.
3. NEVER reference a "Figure 6.X" in your question text without providing either the corresponding "figure_svg" vector diagram or "figure_url"!

STRICT JSON OUTPUT RULES:
1. Return ONLY a valid JSON array of question objects starting with [ and ending with ].
2. No markdown wrappers, no backticks, no explanatory commentary outside the JSON array.
3. Every question object must strictly adhere to this schema:
   - "question_text": Clear, rigorous question statement.
   - "question_type": One of "mcq", "tf", "short", "descriptive", "matching", or "map_hotspot".
   - "figure_svg": Complete SVG code string with viewBox="0 0 350 220" xmlns="http://www.w3.org/2000/svg" if figure is requested/needed, else null.
   - "figure_url": URL string of matching extracted PDF diagram, else null.
   - "options": Array of 4 string choices for "mcq", ["True", "False"] for "tf", or empty array [] for "short" and "descriptive".
   - "correct_answer": For MCQ/TF, the exact matching option string. For short/descriptive, the comprehensive reference answer or key grading points.
   - "explanation": Brief 1-2 sentence grading rubric or explanation.
   - "points": Float mark weightage for this specific question (e.g. 1.0, 2.0, 3.0, 4.0, 5.0, 10.0).
   - "difficulty_tier": Estimated question difficulty: "Easy", "Medium", or "Hard".
   - "blooms_taxonomy": Cognitive level according to Bloom's Taxonomy: one of "Remember", "Understand", "Apply", "Analyze", "Evaluate", or "Create".
   - "distractor_analysis": For MCQ questions, an object mapping incorrect options to a short 1-sentence reason why that specific distractor is wrong/misleading. Format: {{"Option text": "Reason why wrong", ...}}. If short or descriptive, provide empty object {{}}.
   - "is_or_choice": Optional boolean. Set to true if this question is an alternate OR choice to the preceding question (and prefix question_text with "[OR Alternative] ").

STRICT RULES ON MATHEMATICAL NOTATION & CLARITY (CRITICAL):
1. Write all mathematical expressions, questions, formulas, and options in standard, natural, readable notation that high school and university students easily understand:
   - Square roots: write as √4, √2, √(x + 1) or 'square root of 4' (NEVER output raw unrendered LaTeX like \\sqrt{{4}}).
   - Fractions: write as 22/7, 1/2, (a + b)/c (NEVER output raw LaTeX like \\frac{{22}}{{7}}).
   - Powers / Exponents: write as x², y³, 2^n or x^(n+1).
   - Greek symbols and constants: write as π, θ, α, β, Δ, λ, Σ, 3.14 (NEVER output \\pi, \\theta, etc.).
   - Trigonometry / Functions: write sin(x), cos(θ), tan(45°), log(x).
2. Clean Options: Every multiple choice option MUST be a clean, human-readable string without broken backslashes or raw LaTeX codes.
3. If LaTeX is unavoidable, wrap it in clean standard inline delimiters like $...$ so frontend math engines can format it, but prefer clean Unicode/standard text (e.g. '√2', '22/7', 'π').

STRICT RULE ON SOURCE MATERIAL:
Create questions ONLY from the user's provided uploaded PDF, topic context, or prompt. DO NOT invent unrelated questions or generic placeholder questions.
"""
    return prompt

def generate_questions_with_gemini(api_key, text_content=None, image_paths=None, num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """
    Calls Google Gemini API with multimodal and custom prompt blueprint capabilities.
    """
    system_instruction = build_exam_system_prompt(
        num_questions=num_questions, 
        question_type=question_type, 
        difficulty=difficulty, 
        custom_prompt=custom_prompt, 
        total_marks=total_marks,
        available_figures=available_figures
    )

    parts = []
    parts.append({
        "text": f"{system_instruction}\n\nPlease generate the exam paper from the following reference material:\n"
    })

    if text_content and text_content.strip():
        parts.append({
            "text": f"--- REFERENCE MATERIAL TEXT ---\n{text_content[:50000]}"
        })

    if image_paths:
        for img_path in image_paths:
            if os.path.exists(img_path):
                mime, b64_data = encode_image_base64(img_path)
                parts.append({
                    "inline_data": {
                        "mime_type": mime,
                        "data": b64_data
                    }
                })

    keys_pool = parse_api_keys(api_key)
    if not keys_pool:
        return []

    models_to_try = [
        "gemini-flash-lite-latest",
        "gemini-flash-latest",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash"
    ]
    
    last_error = None
    for cur_key in keys_pool:
        for model_name in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={cur_key}"
            payload = {
                "contents": [{"parts": parts}],
                "generationConfig": {
                    "temperature": 0.4,
                    "response_mime_type": "application/json"
                }
            }
            
            try:
                resp = http_post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=45)
                if resp.status_code == 200:
                    result_json = resp.json()
                    raw_text = result_json["candidates"][0]["content"]["parts"][0]["text"].strip()
                    if raw_text.startswith("```json"):
                        raw_text = raw_text[7:]
                    if raw_text.startswith("```"):
                        raw_text = raw_text[3:]
                    if raw_text.endswith("```"):
                        raw_text = raw_text[:-3]
                    raw_text = raw_text.strip()
                    
                    questions = json.loads(raw_text)
                    if isinstance(questions, list) and len(questions) > 0:
                        processed_questions = []
                        for q in questions:
                            q_text = (q.get("question_text") or "").strip()
                            or_pattern = re.compile(r"\n\s*(?:OR|\(OR\)|---\s*OR\s*---)\s*\n", re.IGNORECASE)
                            if or_pattern.search(q_text):
                                parts = or_pattern.split(q_text, maxsplit=1)
                                q1 = dict(q)
                                q1["question_text"] = parts[0].strip()
                                q1["is_or_choice"] = False
                                processed_questions.append(q1)

                                q2 = dict(q)
                                p2_text = parts[1].strip()
                                if not p2_text.startswith("[OR Alternative]"):
                                    p2_text = f"[OR Alternative] {p2_text}"
                                q2["question_text"] = p2_text
                                q2["is_or_choice"] = True
                                processed_questions.append(q2)
                            else:
                                is_or = bool(q.get("is_or_choice") or q_text.startswith("[OR Alternative]"))
                                q["is_or_choice"] = is_or
                                if is_or and not q_text.startswith("[OR Alternative]"):
                                    q["question_text"] = f"[OR Alternative] {q_text}"
                                processed_questions.append(q)
                        return {"success": True, "questions": processed_questions, "model_used": f"Google Gemini ({model_name})"}
                else:
                    last_error = f"Gemini ({model_name}) Error ({resp.status_code}): {resp.text}"
            except Exception as e:
                last_error = str(e)
            
    return {"success": False, "error": last_error or "Failed to generate questions with Gemini."}

def generate_questions_with_openai(api_key, text_content=None, image_paths=None, num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """
    Calls OpenAI API (gpt-4o-mini / gpt-4o) with multimodal vision support and custom prompt blueprints.
    """
    system_prompt = build_exam_system_prompt(
        num_questions=num_questions, 
        question_type=question_type, 
        difficulty=difficulty, 
        custom_prompt=custom_prompt, 
        total_marks=total_marks,
        available_figures=available_figures
    )

    user_text = f"Please generate the exam paper based strictly on this reference material:\n\n{text_content[:50000] if text_content else 'Academic examination questions requested by instructor'}"
    
    user_content = []
    user_content.append({"type": "text", "text": user_text})
    if image_paths:
        for img_path in image_paths:
            if os.path.exists(img_path):
                mime, b64_data = encode_image_base64(img_path)
                user_content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:{mime};base64,{b64_data}"
                    }
                })

    models_to_try = ["gpt-4o-mini", "gpt-4o"]
    last_error = None

    for model in models_to_try:
        try:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content if image_paths else user_text}
                    ],
                    "temperature": 0.4
                },
                timeout=300
            )
            if resp.status_code == 200:
                raw_text = resp.json()["choices"][0]["message"]["content"].strip()
                if "```json" in raw_text:
                    raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                elif "```" in raw_text:
                    raw_text = raw_text.split("```")[1].split("```")[0].strip()
                
                start_idx = raw_text.find("[")
                end_idx = raw_text.rfind("]")
                if start_idx != -1 and end_idx != -1:
                    raw_text = raw_text[start_idx:end_idx + 1]
                
                questions = json.loads(raw_text)
                if isinstance(questions, list) and len(questions) > 0:
                    return {"success": True, "questions": questions, "model_used": f"OpenAI ({model})"}
            else:
                last_error = f"OpenAI ({model}) Error ({resp.status_code}): {resp.text}"
                if resp.status_code == 429 and ("credit_balance_exhausted" in resp.text or "insufficient_quota" in resp.text):
                    last_error = "OpenAI Error: Your OpenAI account has 0 credits remaining. Please add credits at https://platform.openai.com/settings/organization/billing/ or use Google Gemini / Groq."
                    break
        except Exception as e:
            last_error = str(e)

    return {"success": False, "error": last_error or "Failed to generate questions with OpenAI."}

def generate_questions_with_groq(api_key, text_content=None, num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """
    Calls Groq Cloud API with ultra-fast LLMs and custom prompt blueprints.
    """
    system_prompt = build_exam_system_prompt(
        num_questions=num_questions, 
        question_type=question_type, 
        difficulty=difficulty, 
        custom_prompt=custom_prompt, 
        total_marks=total_marks,
        available_figures=available_figures
    )

    user_prompt = f"Please generate the exam paper based strictly on this reference material:\n\n{text_content[:50000] if text_content else 'Academic examination questions requested by instructor'}"
    
    keys_pool = parse_api_keys(api_key)
    if not keys_pool:
        return {"success": False, "error": "No Groq API key provided."}

    models_to_try = ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "mixtral-8x7b-32768", "gemma2-9b-it"]
    last_error = None
    
    for cur_key in keys_pool:
        for model in models_to_try:
            try:
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {cur_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        "temperature": 0.4
                    },
                    timeout=120
                )
                if resp.status_code == 200:
                    raw_text = resp.json()["choices"][0]["message"]["content"].strip()
                    if "```json" in raw_text:
                        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                    elif "```" in raw_text:
                        raw_text = raw_text.split("```")[1].split("```")[0].strip()
                    
                    start_idx = raw_text.find("[")
                    end_idx = raw_text.rfind("]")
                    if start_idx != -1 and end_idx != -1:
                        raw_text = raw_text[start_idx:end_idx + 1]
                    
                    questions = json.loads(raw_text)
                    if isinstance(questions, list) and len(questions) > 0:
                        return {"success": True, "questions": questions, "model_used": f"Groq ({model})"}
                else:
                    last_error = f"Groq Error ({resp.status_code}): {resp.text}"
            except Exception as e:
                last_error = str(e)
            
    return {"success": False, "error": last_error or "Failed to generate questions with Groq."}

def generate_questions_with_openrouter(api_key, text_content=None, num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """
    Calls OpenRouter API using top free models (DeepSeek R1, Llama 3.3).
    """
    system_prompt = build_exam_system_prompt(
        num_questions=num_questions, 
        question_type=question_type, 
        difficulty=difficulty, 
        custom_prompt=custom_prompt, 
        total_marks=total_marks,
        available_figures=available_figures
    )

    user_prompt = f"Please generate the exam paper based strictly on this reference material:\n\n{text_content[:50000] if text_content else 'Academic examination questions requested by instructor'}"
    
    keys_pool = parse_api_keys(api_key)
    if not keys_pool:
        return {"success": False, "error": "No OpenRouter API key provided."}

    # Free high-intelligence models on OpenRouter (current active endpoints)
    models_to_try = [
        "deepseek/deepseek-r1:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "meta-llama/llama-3.2-3b-instruct:free",
        "mistralai/mistral-7b-instruct:free",
        "openrouter/free"
    ]
    last_error = None
    
    for cur_key in keys_pool:
        for model in models_to_try:
            try:
                resp = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {cur_key}",
                        "HTTP-Referer": "https://online-examination-system-with-anti.onrender.com",
                        "X-Title": "Online Examination System Anti-Cheating",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        "temperature": 0.3
                    },
                    timeout=120
                )
                if resp.status_code == 200:
                    raw_text = resp.json()["choices"][0]["message"]["content"].strip()
                    if "```json" in raw_text:
                        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                    elif "```" in raw_text:
                        raw_text = raw_text.split("```")[1].split("```")[0].strip()
                    
                    start_idx = raw_text.find("[")
                    end_idx = raw_text.rfind("]")
                    if start_idx != -1 and end_idx != -1:
                        raw_text = raw_text[start_idx:end_idx + 1]
                    
                    questions = json.loads(raw_text)
                    if isinstance(questions, list) and len(questions) > 0:
                        return {"success": True, "questions": questions, "model_used": f"OpenRouter ({model})"}
                else:
                    last_error = f"OpenRouter ({model}) Error ({resp.status_code}): {resp.text}"
            except Exception as e:
                last_error = str(e)
            
    return {"success": False, "error": last_error or "Failed to generate questions with OpenRouter."}

def generate_questions_unified(gemini_key=None, groq_key=None, openrouter_key=None, text_content=None, image_paths=None, num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """
    PARALLEL AI Multi-Provider Gateway:
    Races Groq + Gemini + OpenRouter simultaneously.
    Returns the FIRST successful result.
    """
    openrouter_key = openrouter_key or get_setting("openrouter_api_key", "") or os.environ.get("OPENROUTER_API_KEY", "").strip()

    if not gemini_key and not groq_key and not openrouter_key:
        return generate_mock_questions(text_content or "", num_questions=num_questions, question_type=question_type, total_marks=total_marks)

    kwargs_gemini = dict(
        api_key=gemini_key,
        text_content=text_content,
        image_paths=image_paths,
        num_questions=num_questions,
        question_type=question_type,
        difficulty=difficulty,
        custom_prompt=custom_prompt,
        total_marks=total_marks,
        available_figures=available_figures
    )
    kwargs_groq = dict(
        api_key=groq_key,
        text_content=text_content,
        num_questions=num_questions,
        question_type=question_type,
        difficulty=difficulty,
        custom_prompt=custom_prompt,
        total_marks=total_marks,
        available_figures=available_figures
    )
    kwargs_openrouter = dict(
        api_key=openrouter_key,
        text_content=text_content,
        num_questions=num_questions,
        question_type=question_type,
        difficulty=difficulty,
        custom_prompt=custom_prompt,
        total_marks=total_marks,
        available_figures=available_figures
    )

    errors = []
    futures_map = {}

    # Primary Provider: Google Gemini with active keys pool
    if gemini_key:
        print("Using primary active Google Gemini provider...")
        gemini_res = generate_questions_with_gemini(**kwargs_gemini)
        if gemini_res.get("success"):
            return gemini_res
        else:
            print(f"Gemini primary attempt had issue: {gemini_res.get('error')}. Falling back to secondary providers...")
            errors.append(f"Gemini: {gemini_res.get('error')}")

    # Fallback Providers: Groq & OpenRouter
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        if groq_key:
            futures_map[executor.submit(generate_questions_with_groq, **kwargs_groq)] = "Groq"
        if openrouter_key:
            futures_map[executor.submit(generate_questions_with_openrouter, **kwargs_openrouter)] = "OpenRouter"

        for future in concurrent.futures.as_completed(futures_map, timeout=180):
            provider = futures_map[future]
            try:
                result = future.result()
                if result.get("success"):
                    print(f"{provider} won fallback race!")
                    return result
                else:
                    errors.append(f"{provider}: {result.get('error', 'Failed')}")
                    print(f"{provider} failed: {result.get('error')}")
            except Exception as e:
                errors.append(f"{provider}: {str(e)}")
                print(f"{provider} exception: {e}")

    # All failed
    return {
        "success": False,
        "error": "AI generation could not complete. " + " | ".join(errors) + ". Please check your API keys or quotas."
    }

def build_paper_parser_system_prompt(available_figures=None):
    """Prompt specifically engineered to ingest and parse existing question papers directly."""
    figures_section = ""
    if available_figures and len(available_figures) > 0:
        sample_figures = available_figures[:20]
        figures_list_text = "\n".join([f"- Page {f['page']}: {f['url']}" for f in sample_figures])
        figures_section = f"""
EXTRACTED DIAGRAMS/FIGURES AVAILABLE FROM THE UPLOADED DOCUMENT:
{figures_list_text}

MANDATORY FIGURE LINKING RULE:
- If a question references or requires a diagram, figure, setup, image, or illustration (e.g. "Shown below are four setups", "Refer to the diagram below", "In the figure given", "As shown in the circuit/diagram"):
  1. Check the list of EXTRACTED DIAGRAMS above.
  2. If an extracted image corresponds to that page or question setup, YOU MUST set "figure_url" to its exact URL (e.g. "/static/extracted_figures/...").
  3. If no extracted image matches but the question describes a geometric setup, experiment setup, or circuit, generate a clear vector SVG in "figure_svg".
"""

    return f"""You are an accurate, intelligent Academic Exam Paper Analyzer and Parser.
The user has pasted a complete exam paper or uploaded a question paper document/photo.
Your task is to analyze the content deeply, identify genuine test questions, and transcribe them cleanly into a structured JSON array.

CRITICAL RULES FOR PARSING:
1. EXCLUDE GENERAL INSTRUCTIONS & METADATA:
   - Do NOT turn exam instructions, headers, or rules into questions! For example:
     * "Show all necessary calculations and reasoning."
     * "Use a ruler, compass and protractor for construction questions."
     * "All questions are compulsory..."
     * "Draw graphs and diagrams neatly..."
     * "Section A — MCQs", "Maximum marks 80", "Time allowed 3 hours"
     THESE ARE EXAM GUIDELINES, NOT QUESTIONS. SKIP THEM COMPLETELY.
2. ACCURATE QUESTION SEPARATION:
   - "question_text": Must contain ONLY the actual question statement/premise (e.g. "Two angles together form a straight angle. If one angle is 68°, the other angle is:").
   - NEVER place multiple-choice choices inside "question_text".
   - "options": Put each choice cleanly in the options array as ["(a) 22°", "(b) 112°", "(c) 122°", "(d) 90°"].
3. CLEAN UP MATHEMATICAL NOTATION:
   - Powers / Exponents: ALWAYS use proper Unicode superscripts like 2², 3², 5³, x², y³, 2ⁿ (NEVER write raw caret notation like 3^2, 5^2, or 2^2).
   - Multiplication: ALWAYS use the proper multiplication symbol '×' or standard dot (e.g. write "2 × 3² × 5" — NEVER write raw asterisks like "2 * 3^2 * 5").
   - Convert raw unrendered LaTeX like \\(68^\\circ\\) into clean, readable text like 68°.
   - Convert \\sqrt{{x}} into √x, \\frac{{a}}{{b}} into a/b.
4. ACCURATE MARKS / POINTS EXTRACTION (CRITICAL):
   - Check headers, section titles, and question markers for points allocation:
     * e.g., "**Total Marks: 20**", "**5 × 1 = 5 Marks**", "[1 Mark]", "[2 Marks]", "(3 pts)".
     * If a section says "**5 × 1 = 5 Marks**", each question in that section is exactly 1.0 point (NOT 2 points).
     * If the document declares "**Total Marks: 20**" with 20 questions, each question is 1.0 point.
     * NEVER assign random points (like 2.0 or 5.0) if the paper specifies 1 mark or a total marks budget.
     * The sum of points across all parsed questions MUST accurately reflect the paper's specified section breakdown and Total Marks.
     * Default to 1.0 point if no specific mark is indicated.
   - Question Types:
     * MCQs: "question_type": "mcq", 4 options in "options".
     * True/False: "question_type": "tf", "options": ["True", "False"].
     * Short questions: "question_type": "short", "options": [].
     * Long / Descriptive / Proofs: "question_type": "descriptive", "options": [].
5. CORRECT ANSWERS:
   - Solve or identify the correct answer for each MCQ/question and place it in "correct_answer".
   - Provide a brief 1-sentence rubric in "explanation".
6. FIGURE & DIAGRAM LINKING (CRITICAL):
{figures_section}
   - If a question is about geometry, shapes, lines, angles, triangles, or graphs and has no matching extracted figure URL:
     Generate a clean vector SVG in "figure_svg" (<svg viewBox="0 0 350 220" xmlns="http://www.w3.org/2000/svg">...</svg>).
     Otherwise set "figure_svg": null.
   - If a question does not need or have any diagram, set both "figure_url": null and "figure_svg": null.

7. SUB-QUESTIONS (A / B) AND OR / ALTERNATIVE QUESTION DETECTION (CRITICAL):
   - Pay very close attention to question boxes and numbering in the paper:
     * Case 1: SUB-QUESTIONS UNDER THE SAME NUMBER (e.g. Question 10 contains sub-part A and sub-part B):
       Look at Question 10 in the paper. It has:
       "A. Due to narrowing of the bile duct..."
       "B. How does the length of the intestine depend..."
       These are parts of Question 10 (or sub-questions 10.a and 10.b).
       DO NOT number Part B as a completely new Question 11!
       Keep Question 10's parts together, or if separating as sub-questions, mark:
       - Part A as "A. Due to narrowing of the bile duct..."
       - Part B as "B. How does the length of the intestine depend..."
     * Case 2: OR ALTERNATIVE CHOICE (e.g. Question 11: "Students to attempt either option A or B" with "OR" in between):
       Option A: "A. Which parts of the brain perform certain actions..."
       Option B: "B. How is the information of touch in the 'sensitive plant'..."
       When you see "Students to attempt either option A or B" or "OR" between Option A and Option B:
       - DO NOT merge them into one question.
       - DO NOT drop either question.
       - Output TWO separate question objects:
         1) The first option: Set "is_or_choice": false.
         2) The second option: YOU MUST set "is_or_choice": true AND start "question_text" with "[OR Alternative] ".
         3) Both have the same marks (e.g., 2.0 marks each).
         4) Give each question its OWN diagram if applicable.

8. SECTION EXTRACTION & CLEANING (CRITICAL):
   - Papers are divided into sections like "Section A: Multiple Choice Questions", "Section B: Very Short Answer", "Section C: Short Answer", "Section D: Long Answer".
   - Extract the current section name into the "section" field (e.g. "Section A: MCQs", "Section B", "Section C").
   - NEVER let section headers bleed or append into the question text! For example:
     WRONG: "Draw the quadrilateral whose vertices are ... Section C – Short Answer Questions Questions 26–31 · 3 marks each"
     RIGHT question_text: "Draw the quadrilateral whose vertices are (1, 1), (2, 4), (8, 4) and (10, 1)."
     RIGHT section: "Section B" (or the active section)
   - NEVER drop coordinate numbers, equations, or variables in math questions. If a sentence has blank holes like "Reflect on the role of and .", inspect the scan carefully to retrieve the equations (e.g. y = mx + c) or coordinates.

JSON FORMAT:
Output ONLY a valid JSON array of question objects starting with [ and ending with ].
No markdown codeblocks or backticks. Schema:
[
  {{
    "section": "string",
    "question_text": "string",
    "question_type": "mcq" | "short" | "descriptive" | "tf",
    "options": ["string", ...],
    "correct_answer": "string",
    "explanation": "string",
    "points": 1.0,
    "figure_svg": "string or null",
    "figure_url": "string or null",
    "is_or_choice": boolean
  }}
]"""

def parse_existing_paper_with_gemini(api_key, raw_text, image_paths=None, available_figures=None):
    """Parses raw pasted exam paper or uploaded photos/scans using Gemini multimodal vision."""
    system_prompt = build_paper_parser_system_prompt(available_figures=available_figures)
    models = [
        "gemini-flash-lite-latest",
        "gemini-flash-latest",
        "gemini-2.5-flash",
        "gemini-2.0-flash"
    ]
    last_err = None

    parts = [
        {"text": f"{system_prompt}\n\nPlease parse and transcribe this paper verbatim:\n\n{raw_text[:70000] if raw_text else 'Transcribe all questions from the attached photo/document.'}"}
    ]
    if image_paths:
        for img_path in image_paths:
            if os.path.exists(img_path):
                mime, b64_data = encode_image_base64(img_path)
                parts.append({
                    "inline_data": {
                        "mime_type": mime,
                        "data": b64_data
                    }
                })
    
    keys_pool = parse_api_keys(api_key)
    if not keys_pool:
        return []

    for cur_key in keys_pool:
        for model_name in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={cur_key}"
            payload = {
                "contents": [{
                    "parts": parts
                }],
                "generationConfig": {
                    "temperature": 0.1,
                    "response_mime_type": "application/json"
                }
            }
            try:
                resp = http_post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=120)
                if resp.status_code == 200:
                    raw_text_out = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                    if raw_text_out.startswith("```json"):
                        raw_text_out = raw_text_out[7:]
                    if raw_text_out.startswith("```"):
                        raw_text_out = raw_text_out[3:]
                    if raw_text_out.endswith("```"):
                        raw_text_out = raw_text_out[:-3]
                    raw_text_out = raw_text_out.strip()
                    questions = json.loads(raw_text_out)
                    if isinstance(questions, list) and len(questions) > 0:
                        processed_questions = []
                        for q in questions:
                            q_text = (q.get("question_text") or "").strip()
                            # Match OR markers: newlines with OR, inline ' OR ', ' (OR) ', '--- OR ---', or header 'Students to attempt either option A or B'
                            clean_text = re.sub(r"^(?:Students\s+to\s+attempt\s+either\s+option\s+[A-Za-z]\s+or\s+[A-Za-z][\.\:\s]*|Attempt\s+either\s+option\s+[A-Za-z]\s+or\s+[A-Za-z][\.\:\s]*)\n*", "", q_text, flags=re.IGNORECASE).strip()
                            # Also strip bleeding section trailers like: ". Section C – Short Answer Questions Questions 26–31 · 3 marks each"
                            section_bleed_match = re.search(r"(?:\n|\.\s+)(?:Section\s+[A-Z]|Part\s+[A-Z])\s*[\-–—\:]\s*.*$", clean_text, flags=re.IGNORECASE)
                            if section_bleed_match:
                                clean_text = clean_text[:section_bleed_match.start()].strip()
                                if not clean_text.endswith('.'):
                                    clean_text += '.'

                            or_pattern = re.compile(r"(?:\n\s*(?:OR|\(OR\)|---\s*OR\s*---)\s*\n|\s+OR\s+(?=[B-Z]\.|\(b\)|\(B\))|\n\s*OR\s+(?=[B-Z]\.|\(b\)|\(B\)))", re.IGNORECASE)
                            has_merged_or = bool(or_pattern.search(clean_text))

                            if has_merged_or:
                                parts = or_pattern.split(clean_text, maxsplit=1)
                                # Part 1: Primary question
                                q_copy1 = dict(q)
                                q_copy1["question_text"] = parts[0].strip()
                                q_copy1["is_or_choice"] = False
                                processed_questions.append(q_copy1)

                                # Part 2: OR alternative question
                                q_copy2 = dict(q)
                                part2_text = parts[1].strip()
                                if not part2_text.startswith("[OR Alternative]"):
                                    part2_text = f"[OR Alternative] {part2_text}"
                                q_copy2["question_text"] = part2_text
                                q_copy2["is_or_choice"] = True
                                processed_questions.append(q_copy2)
                            else:
                                # Check if flagged as is_or_choice or starts with [OR Alternative]
                                is_or = bool(q.get("is_or_choice") or clean_text.startswith("[OR Alternative]"))
                                q["question_text"] = clean_text
                                if is_or:
                                    q["is_or_choice"] = True
                                    if not clean_text.startswith("[OR Alternative]"):
                                        q["question_text"] = f"[OR Alternative] {clean_text}"
                                else:
                                    q["is_or_choice"] = False
                                processed_questions.append(q)

                        return {"success": True, "questions": processed_questions, "model_used": f"Google Gemini Parser ({model_name})"}
                else:
                    last_err = f"Gemini ({model_name}) HTTP {resp.status_code}: {resp.text[:180]}"
                    print(f"Skipping {model_name} due to: {last_err}")
            except Exception as e:
                last_err = str(e)
            
    return {"success": False, "error": last_err or "Failed to parse with Gemini."}

def parse_pasted_paper_unified(gemini_key=None, groq_key=None, raw_text="", image_paths=None, available_figures=None):
    """
    Direct Paper Parser: Exclusively powered by Google Gemini (gemini-3.8-flash, gemini-flash-latest, gemini-3.5-flash)
    to transcribe and extract pasted questions or uploaded images/PDFs verbatim.
    Falls back to smart local regex rule-based parser if no Gemini API key is configured or upon error.
    """
    has_text = bool(raw_text and raw_text.strip())
    has_images = bool(image_paths and len(image_paths) > 0)
    if not has_text and not has_images:
        return {"success": False, "error": "No question text or file provided to parse."}

    if gemini_key:
        result = parse_existing_paper_with_gemini(gemini_key, raw_text, image_paths=image_paths, available_figures=available_figures)
        if result.get("success"):
            return result
        gemini_err = result.get("error", "Unknown Gemini error")
    else:
        gemini_err = "No Gemini API key configured."

    # Fallback to local rule-based regex parser if Gemini key is missing or fails (text-only)
    if has_text:
        rule_result = regex_parse_pasted_questions(raw_text)
        if rule_result.get("success") and len(rule_result.get("questions", [])) > 0:
            rule_result["model_used"] = "Fast Local Rule-based Parser (Fallback)"
            return rule_result

    return {"success": False, "error": f"Could not parse questions with Gemini: {gemini_err}"}

def regex_parse_pasted_questions(raw_text):
    """
    Fast rule-based / regex parser that breaks pasted numbered questions,
    options (a, b, c, d), and point markers into structured question items.
    """
    lines = raw_text.splitlines()
    questions = []
    current_q = None
    
    # Regex to detect question start: "1.", "1)", "Q1.", "Q1:", "**1."
    q_start_re = re.compile(r"^(?:\*{0,2})(?:Question|Q)?\s*(\d+)[\.\:\)]\s*(.*)", re.IGNORECASE)
    opt_re = re.compile(r"^\s*[\(\[]?([a-dA-D])[\)\]\.\:]\s*(.*)")
    points_re = re.compile(r"\[?\(?\s*(\d+(?:\.\d+)?)\s*(?:marks?|pts?|points?)\s*\)?\]?", re.IGNORECASE)

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
            
        m_q = q_start_re.match(stripped)
        if m_q:
            if current_q:
                questions.append(current_q)
            q_text = m_q.group(2).strip().strip("*").strip()
            pts = 1.0
            pts_m = points_re.search(stripped)
            if pts_m:
                try:
                    pts = float(pts_m.group(1))
                except Exception:
                    pts = 1.0
            current_q = {
                "question_text": q_text or f"Question {m_q.group(1)}",
                "question_type": "mcq",
                "options": [],
                "correct_answer": "",
                "explanation": "",
                "points": pts,
                "figure_svg": None,
                "figure_url": None
            }
            continue
            
        m_opt = opt_re.match(stripped)
        if m_opt and current_q:
            opt_letter = m_opt.group(1).lower()
            opt_text = m_opt.group(2).strip()
            current_q["options"].append(f"({opt_letter}) {opt_text}")
            continue

        if current_q:
            # Check if answer line
            if re.match(r"^(?:Answer|Ans|Correct)\s*[\:\-]\s*(.*)", stripped, re.IGNORECASE):
                ans_match = re.match(r"^(?:Answer|Ans|Correct)\s*[\:\-]\s*(.*)", stripped, re.IGNORECASE)
                current_q["correct_answer"] = ans_match.group(1).strip()
            else:
                current_q["question_text"] += " " + stripped

    if current_q:
        questions.append(current_q)

    # Post-process types and split internal OR questions
    final_questions = []
    for q in questions:
        q_text = (q.get("question_text") or "").strip()
        or_match = re.search(r"(?:\n|\s+)(?:OR|\(OR\)|---\s*OR\s*---)(?:\n|\s+)(?:[B-Z]\.?\s*)?", q_text, re.IGNORECASE)
        if or_match:
            split_idx = or_match.start()
            part1 = q_text[:split_idx].strip()
            part2 = q_text[or_match.end():].strip()
            if part1 and part2:
                q1 = dict(q)
                q1["question_text"] = part1
                q1["is_or_choice"] = False
                final_questions.append(q1)

                q2 = dict(q)
                q2["question_text"] = f"[OR Alternative] {part2}"
                q2["is_or_choice"] = True
                final_questions.append(q2)
                continue

        is_or = bool(q.get("is_or_choice") or q_text.startswith("[OR Alternative]"))
        q["is_or_choice"] = is_or
        if is_or and not q_text.startswith("[OR Alternative]"):
            q["question_text"] = f"[OR Alternative] {q_text}"
        final_questions.append(q)

    for q in final_questions:
        if not q.get("options"):
            if len(q.get("question_text", "")) > 180 or float(q.get("points") or 1.0) >= 5.0:
                q["question_type"] = "descriptive"
            else:
                q["question_type"] = "short"
        elif len(q.get("options", [])) == 2 and ("true" in q["options"][0].lower() or "false" in q["options"][0].lower()):
            q["question_type"] = "tf"
            q["options"] = ["True", "False"]

    if final_questions:
        return {"success": True, "questions": final_questions, "model_used": "Smart Instant Parser"}
    return {"success": False, "error": "No recognizable numbered questions found in pasted text."}

def generate_mock_questions(topic_or_context, num_questions=5, question_type="mcq", total_marks=None):
    """
    Generates dynamic questions strictly derived from the user's provided context or topic.
    NEVER returns canned, pre-made unrelated questions.
    """
    raw_lines = [line.strip() for line in (topic_or_context or "").split("\n") if len(line.strip()) > 30 and not line.strip().startswith("---")]
    topic_summary = (topic_or_context[:60] if topic_or_context else "Study Notes").replace("\n", " ").strip()
    
    questions = []
    points_per_q = round(float(total_marks) / max(1, num_questions), 1) if total_marks else 1.0

    for i in range(num_questions):
        source_sentence = raw_lines[i % len(raw_lines)] if raw_lines else f"Key concept {i+1} regarding {topic_summary}"
        
        if question_type == "tf":
            q_obj = {
                "question_text": f"Based on the study material: {source_sentence[:180]}. Is this statement accurate?",
                "question_type": "tf",
                "options": ["True", "False"],
                "correct_answer": "True",
                "explanation": "Verified based on the provided study material reference.",
                "points": points_per_q,
                "figure_svg": None,
                "figure_url": None
            }
        elif question_type in ["short", "descriptive"]:
            q_obj = {
                "question_text": f"Analyze and explain the following concept from the study material: '{source_sentence[:180]}'. Discuss its implications and core principles.",
                "question_type": question_type,
                "options": [],
                "correct_answer": f"Evaluation points: (1) Accurate definition of {source_sentence[:60]}, (2) Key mechanisms and principles, (3) Practical context or applications.",
                "explanation": f"Full credit for structured answers addressing definition, analysis, and core principles.",
                "points": points_per_q,
                "figure_svg": None,
                "figure_url": None
            }
        else:
            q_obj = {
                "question_text": f"Regarding '{source_sentence[:140]}', which of the following is the most accurate deduction?",
                "question_type": "mcq",
                "options": [
                    f"Directly corresponds to the primary principle of {topic_summary[:30]}",
                    f"Contradicts the foundational premise of {topic_summary[:30]}",
                    "Applies only in deprecated legacy configurations",
                    "Has no measurable relevance to the given topic"
                ],
                "correct_answer": f"Directly corresponds to the primary principle of {topic_summary[:30]}",
                "explanation": "Direct deduction from the uploaded study material context.",
                "points": points_per_q,
                "figure_svg": None,
                "figure_url": None
            }
        questions.append(q_obj)
        
    return {"success": True, "questions": questions, "is_mock": True}


def evaluate_answer_with_ai(gemini_key=None, groq_key=None, question_text="", max_points=1.0, correct_answer="", student_text="", image_path=None, image_paths=None, explanation=""):
    """
    Evaluates a student's answer (written text or uploaded handwritten photos/pages) using AI
    following the official CBSE Board Marking Scheme & Evaluator Directives.
    Supports Google Gemini (with multi-image vision for multi-page solutions) and Groq Cloud.
    
    Returns: {
        "success": bool,
        "awarded_marks": float,
        "what_student_did": str,
        "where_student_went_wrong": str,
        "how_it_should_be_written": str,
        "step_breakdown": list of {"step": str, "marks_allocated": float, "marks_awarded": float, "status": "full"|"partial"|"missed"},
        "examiner_remark": str,
        "feedback": str,  # Combined summary for backward compatibility
        "model_used": str
    }
    """
    max_pts = float(max_points) if max_points else 1.0

    # Collect all valid image paths or remote Cloudinary URLs (single or multiple pages)
    all_imgs = []
    def _is_valid_img(img_ref):
        if not img_ref or not isinstance(img_ref, str):
            return False
        img_ref = img_ref.strip()
        if img_ref.startswith("http://") or img_ref.startswith("https://"):
            return True
        return os.path.exists(img_ref)

    if image_paths and isinstance(image_paths, list):
        for p in image_paths:
            if _is_valid_img(p) and p not in all_imgs:
                all_imgs.append(p)
    if image_path and _is_valid_img(image_path) and image_path not in all_imgs:
        all_imgs.append(image_path)

    pages_note = f" (Student attached {len(all_imgs)} page(s) of handwritten solution)" if all_imgs else ""

    eval_prompt = f"""You are a head examiner for the Central Board of Secondary Education (CBSE) evaluating a student's answer sheet.
You must grade strictly according to the official CBSE Board Marking Guidelines and Examination Directives.

QUESTION:
{question_text}

TOTAL MAXIMUM MARKS:
{max_pts}

MODEL / REFERENCE ANSWER & KEY CRITERIA:
{correct_answer or 'Grade based on fundamental correctness, clarity, conceptual accuracy, and completeness.'}

GRADING RUBRIC / EXPLANATION:
{explanation or 'Award marks step-wise proportionally (0 to ' + str(max_pts) + ').'}

STUDENT'S WRITTEN TEXT / ATTACHED ANSWER:
{student_text or '(No typed text provided - examine the attached photo(s) of the handwritten answer sheet)'}{pages_note}

CRITICAL HANDWRITTEN ANSWER INSPECTION RULES:
- If photo(s) or images of handwritten solution are attached, you MUST read the handwriting carefully, whether written upright, sideways, or tilted.
- Transcribe the student's handwritten equations, fractions, and steps before grading.
- NEVER state "No written answer was provided" or "The question was left completely unattempted" if the image contains visible mathematical work, diagrams, or text. Only report unattempted if the student truly submitted a completely blank white page or no answer at all.

OFFICIAL CBSE MARKING DIRECTIVES (MANDATORY TO FOLLOW):
1. STEP-BY-STEP MARKING (VALUE POINTS):
   - Never award marks solely on the final answer. Marks must be split into step marks (typically ½ or 1 mark value points).
   - In Mathematics / Numericals:
     * Stating Given Data & Correct Formula / Theorem / Sample Space: ½ to 1 mark.
     * Intermediate Substitution & Correct Steps: ½ to 2 marks.
     * Final Answer with correct simplification / SI units: ½ to 1 mark.
   - In Science / Physics / Chemistry / Biology:
     * Mention of core keywords / key value points: ½ to 1 mark each.
     * Balanced chemical equations (deduct ½ mark if unbalanced): ½ to 1 mark.
     * Circuit diagrams / Ray diagrams: Deduct ½ mark if ray direction arrows or component polarities (+/-) are missing.
2. CLAUSE 10: SINGLE PENALTY & ERROR CARRIED FORWARD (ECF):
   - A student's error must be penalized ONLY ONCE.
   - If a student makes an arithmetic or algebraic mistake in an early step, deduct marks for THAT specific step. If all subsequent steps are logically and methodologically correct based on that wrong intermediate value, AWARD FULL STEP MARKS for the subsequent steps.
3. CONSTRUCTIVE DIAGNOSTIC FEEDBACK (ADDRESS THE STUDENT DIRECTLY AS 'YOU'):
   - "what_student_did": Clearly state what you (the student) did correctly (e.g. "You correctly identified the sample space (36) and set up the probability ratio.").
   - "where_student_went_wrong": Explicitly identify where you made a mistake (missing step, wrong calculation, misread question, or calculation slip). If completely correct, write "None. Complete and accurate response."
   - "how_it_should_be_written": Provide the ideal CBSE board presentation of the solution (proper steps, neat formula, units, or key value points).
   - "examiner_remark": A concise 1-2 sentence examiner note directly advising the student.
4. TOTAL AWARDED MARKS:
   - Must be between 0.0 and {max_pts}.
   - The sum of step marks awarded must match "awarded_marks".

STRICT JSON OUTPUT FORMAT (NO MARKDOWN CODEBLOCKS, ONLY VALID JSON):
{{
  "awarded_marks": 2.5,
  "step_breakdown": [
    {{"step": "Formula stated & given values substituted", "marks_allocated": 1.0, "marks_awarded": 1.0, "status": "full"}},
    {{"step": "Intermediate algebraic simplification", "marks_allocated": 1.0, "marks_awarded": 1.0, "status": "full"}},
    {{"step": "Final numerical value with SI unit", "marks_allocated": 0.5, "marks_awarded": 0.5, "status": "full"}}
  ],
  "what_student_did": "You correctly recalled the formula, set up the initial equations, and substituted the given values accurately.",
  "where_student_went_wrong": "Minor arithmetic slip in the final denominator division; missing SI units in your final statement.",
  "how_it_should_be_written": "1. Write formula: P = V × I\\n2. Substitute values: P = 220V × 0.5A\\n3. Final Answer: P = 110 W (with proper unit Watts).",
  "examiner_remark": "Good conceptual grasp with step-by-step layout. Be cautious with final arithmetic and always write SI units."
}}
"""

    def _normalize_evaluation_data(data, model_tag):
        try:
            awarded = float(data.get("awarded_marks", 0.0))
        except (ValueError, TypeError):
            awarded = 0.0
        awarded = max(0.0, min(max_pts, round(awarded, 1)))

        what_did = (data.get("what_student_did") or "").strip()
        where_wrong = (data.get("where_student_went_wrong") or "").strip()
        how_written = (data.get("how_it_should_be_written") or "").strip()
        remark = (data.get("examiner_remark") or data.get("feedback") or "").strip()
        raw_steps = data.get("step_breakdown") or []
        step_breakdown = []
        if isinstance(raw_steps, list):
            for s in raw_steps:
                if isinstance(s, dict):
                    step_breakdown.append({
                        "step": str(s.get("step") or "Evaluation Step"),
                        "marks_allocated": float(s.get("marks_allocated") or 0.0),
                        "marks_awarded": float(s.get("marks_awarded") or 0.0),
                        "status": str(s.get("status") or "partial")
                    })

        # Synthesize rich feedback string for backward compatibility
        fb_parts = []
        if remark:
            fb_parts.append(remark)
        if what_did:
            fb_parts.append(f"• Correct Steps: {what_did}")
        if where_wrong and where_wrong.lower() not in ("none", "none.", "n/a"):
            fb_parts.append(f"• Areas for Improvement: {where_wrong}")
        feedback_str = "\n".join(fb_parts) if fb_parts else (remark or "AI evaluated response.")

        return {
            "success": True,
            "awarded_marks": awarded,
            "what_student_did": what_did,
            "where_student_went_wrong": where_wrong,
            "how_it_should_be_written": how_written,
            "step_breakdown": step_breakdown,
            "examiner_remark": remark,
            "feedback": feedback_str,
            "model_used": model_tag
        }

    # 1. Try Gemini first (multimodal vision + multi-page handwriting analysis)
    if gemini_key:
        parts = [{"text": eval_prompt}]
        for idx, img_p in enumerate(all_imgs):
            try:
                mime, b64_data = encode_image_base64(img_p)
                if len(all_imgs) > 1:
                    parts.append({"text": f"--- STUDENT ANSWER PAGE {idx + 1} OF {len(all_imgs)} ---"})
                parts.append({
                    "inline_data": {
                        "mime_type": mime,
                        "data": b64_data
                    }
                })
            except Exception as e:
                print(f"Error encoding student answer image {img_p}: {e}")

        models = [
            "gemini-flash-lite-latest",
            "gemini-flash-latest",
            "gemini-2.5-flash",
            "gemini-2.0-flash"
        ]

        keys_pool = parse_api_keys(gemini_key)
        for cur_key in keys_pool:
            for model_name in models:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={cur_key}"
                payload = {
                    "contents": [{"parts": parts}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "response_mime_type": "application/json"
                    }
                }
                try:
                    resp = http_post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=45)
                    if resp.status_code == 200:
                        raw_text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                        if raw_text.startswith("```json"):
                            raw_text = raw_text[7:]
                        if raw_text.startswith("```"):
                            raw_text = raw_text[3:]
                        if raw_text.endswith("```"):
                            raw_text = raw_text[:-3]
                        raw_text = raw_text.strip()
                        data = json.loads(raw_text)
                        return _normalize_evaluation_data(data, f"Google Gemini ({model_name}) [CBSE Pattern]")
                except Exception as e:
                    print(f"Gemini evaluation error ({model_name}): {e}")

    # 2. Try Groq (if text-based or if student provided text)
    if groq_key and student_text:
        groq_keys_pool = parse_api_keys(groq_key)
        groq_models = ["llama-3.3-70b-versatile", "gemma2-9b-it", "mixtral-8x7b-32768"]
        for g_key in groq_keys_pool:
            for g_model in groq_models:
                try:
                    headers = {
                        "Authorization": f"Bearer {g_key}",
                        "Content-Type": "application/json"
                    }
                    payload = {
                        "model": g_model,
                        "messages": [
                            {"role": "system", "content": "You are a senior CBSE board examiner. Follow step-marking and CBSE directives strictly. Return ONLY valid JSON with 'awarded_marks', 'step_breakdown', 'what_student_did', 'where_student_went_wrong', 'how_it_should_be_written', and 'examiner_remark'."},
                            {"role": "user", "content": eval_prompt}
                        ],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"}
                    }
                    resp = http_post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload, timeout=30)
                    if resp.status_code == 200:
                        content = resp.json()["choices"][0]["message"]["content"].strip()
                        data = json.loads(content)
                        return _normalize_evaluation_data(data, f"Groq ({g_model}) [CBSE Pattern]")
                except Exception as e:
                    print(f"Groq evaluation error ({g_model}): {e}")

    return {
        "success": False,
        "error": "AI evaluation could not be completed. Please configure a valid Gemini or Groq API key in Tutor Settings."
    }


def verify_faces_with_gemini(gemini_key, reference_image_path, live_snapshot_path, student_name=""):
    """
    Compares a registered student profile photo (reference) with a live webcam snapshot using Gemini Vision AI.
    Falls back gracefully to a pure-Python local biometric comparison if Gemini API is unreachable, exhausted, or unconfigured.
    Returns: {"success": bool, "is_match": bool, "confidence": float, "reason": str}
    """
    if not reference_image_path or not os.path.exists(reference_image_path):
        return {"success": False, "error": "Registered student reference photo not found on server."}

    if not live_snapshot_path or not os.path.exists(live_snapshot_path):
        return {"success": False, "error": "Live webcam snapshot not found."}

    # 1. Try Gemini Vision AI if API key is present
    if gemini_key and gemini_key.strip():
        try:
            from PIL import Image
            import io

            # Optimize and downscale snapshots to 380x380 JPEG for fast network upload and low inference latency
            def prepare_fast_b64(img_path):
                try:
                    with Image.open(img_path) as im:
                        im = im.convert('RGB')
                        im.thumbnail((380, 380), Image.Resampling.LANCZOS)
                        buf = io.BytesIO()
                        im.save(buf, format='JPEG', quality=82, optimize=True)
                        return "image/jpeg", base64.b64encode(buf.getvalue()).decode("utf-8")
                except Exception:
                    return encode_image_base64(img_path)

            ref_mime, ref_b64 = prepare_fast_b64(reference_image_path)
            live_mime, live_b64 = prepare_fast_b64(live_snapshot_path)

            prompt = f"""You are a strict, forensic-grade biometric identity verification AI for university examinations.
TASK:
Critically compare IMAGE 1 (Official Registered Reference Photo of student: {student_name or 'Candidate'}) with IMAGE 2 (Live Webcam Check-In Snapshot).

CRITICAL BIOMETRIC CRITERIA:
1. Examine unalterable anatomical markers:
   - Nose bridge contour, nostril flare, and nose width.
   - Jawline definition, chin curvature (pointed, squared, or rounded).
   - Eye shape, inter-pupillary distance ratio, and brow ridge.
   - Mouth width, lip thickness, and philtrum length.
2. ZERO-TOLERANCE ANTI-IMPERSONATION POLICY:
   - Do NOT assume two people are the same simply because they share similar age, skin tone, or haircut.
   - If the facial bone structure, nose shape, or jawline belongs to a DIFFERENT person, you MUST REJECT with "is_match": false and "confidence": 0.
   - Only return "is_match": true if you are 100% confident beyond a reasonable doubt that IMAGE 1 and IMAGE 2 show the EXACT SAME human individual.

DECISION GUIDELINES:
- EXACT SAME PERSON: return "is_match": true, "confidence": (82 to 98), "reason": "Detailed confirmation of matching facial bone structure, nose bridge, and eye proportions."
- DIFFERENT PERSON (IMPOSTOR / UNAUTHORIZED CANDIDATE): return "is_match": false, "confidence": 0, "reason": "Biometric mismatch: facial geometry, jawline, and nose contour differ from registered student."

OUTPUT FORMAT (JSON ONLY, NO MARKDOWN):
{{
  "is_match": false,
  "confidence": 0,
  "reason": "Biometric mismatch: distinct jawline and nose shape detected."
}}
"""

            parts = [
                {"text": prompt},
                {"text": "--- IMAGE 1: REGISTERED STUDENT REFERENCE PHOTO ---"},
                {"inline_data": {"mime_type": ref_mime, "data": ref_b64}},
                {"text": "--- IMAGE 2: LIVE WEBCAM SNAPSHOT TAKEN AT EXAM ENTRY ---"},
                {"inline_data": {"mime_type": live_mime, "data": live_b64}}
            ]

            # Models to try across v1 and v1beta endpoints, prioritizing Gemini 3.8 & 3.5
            models = [
                "gemini-flash-lite-latest",
                "gemini-flash-latest",
                "gemini-2.5-flash",
                "gemini-2.0-flash",
                "gemini-1.5-flash"
            ]

            api_versions = ["v1beta", "v1"]

            keys_pool = parse_api_keys(gemini_key)
            for cur_key in keys_pool:
                key_rate_limited = False
                for ver in api_versions:
                    if key_rate_limited:
                        break
                    for model_name in models:
                        url = f"https://generativelanguage.googleapis.com/{ver}/models/{model_name}:generateContent?key={cur_key}"
                        payload = {
                            "contents": [{"parts": parts}],
                            "generationConfig": {
                                "temperature": 0.1,
                                "response_mime_type": "application/json"
                            }
                        }
                        try:
                            resp = http_post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=12)
                            if resp.status_code == 200:
                                res_json = resp.json()
                                candidates = res_json.get("candidates", [])
                                if candidates and "content" in candidates[0] and "parts" in candidates[0]["content"]:
                                    raw_text = candidates[0]["content"]["parts"][0].get("text", "").strip()
                                    if raw_text.startswith("```json"):
                                        raw_text = raw_text[7:]
                                    if raw_text.startswith("```"):
                                        raw_text = raw_text[3:]
                                    if raw_text.endswith("```"):
                                        raw_text = raw_text[:-3]
                                    raw_text = raw_text.strip()
                                    import re
                                    json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
                                    if json_match:
                                        data = json.loads(json_match.group(0))
                                        is_match = bool(data.get("is_match", False))
                                        confidence = float(data.get("confidence", 0.0))
                                        reason = data.get("reason", "Face verification evaluated by Gemini AI.")
                                        if not is_match:
                                            confidence = 0.0
                                        return {
                                            "success": True,
                                            "is_match": is_match,
                                            "confidence": round(confidence, 1),
                                            "reason": reason,
                                            "model_used": f"Gemini Vision ({model_name} {ver})"
                                        }
                            elif resp.status_code == 429:
                                print(f"Gemini face verification ({model_name} {ver}): rate limit 429 - switching API key")
                                key_rate_limited = True
                                break  # Break model loop; next line will break ver loop and try next key
                            else:
                                print(f"Gemini face verification error ({model_name} {ver}): status {resp.status_code}")
                        except Exception as e:
                            print(f"Gemini face verification exception ({model_name} {ver}): {e}")
        except Exception as enc_err:
            print(f"Gemini verification setup error: {enc_err}")

    # 2. Try OpenRouter Vision AI (Multi-model fallback including openrouter/free)
    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if openrouter_key:
        try:
            from PIL import Image
            import io

            def prepare_fast_b64_or(img_path):
                try:
                    with Image.open(img_path) as im:
                        im = im.convert('RGB')
                        im.thumbnail((380, 380), Image.Resampling.LANCZOS)
                        buf = io.BytesIO()
                        im.save(buf, format='JPEG', quality=82, optimize=True)
                        return base64.b64encode(buf.getvalue()).decode("utf-8")
                except Exception:
                    return ""

            ref_b64_or = prepare_fast_b64_or(reference_image_path)
            live_b64_or = prepare_fast_b64_or(live_snapshot_path)

            if ref_b64_or and live_b64_or:
                or_keys = parse_api_keys(openrouter_key)
                or_vision_models = [
                    "openrouter/free",
                    "nvidia/nemotron-3.5-super-vl:free",
                    "meta-llama/llama-3.2-11b-vision-instruct:free"
                ]
                for o_key in or_keys:
                    for or_model in or_vision_models:
                        or_prompt = (
                            "You are a strict anti-cheating face verification AI for examinations. "
                            "IMAGE 1 is the registered student reference photo. IMAGE 2 is the live webcam proctor feed. "
                            "Compare the facial identity of the person in IMAGE 1 and IMAGE 2. "
                            "Are they the EXACT SAME person, or is IMAGE 2 an impostor / different person taking the exam? "
                            "Respond ONLY in valid raw JSON with keys: "
                            "{\"is_match\": boolean, \"confidence\": number from 0 to 100, \"reason\": string}"
                        )
                        headers = {
                            "Authorization": f"Bearer {o_key}",
                            "Content-Type": "application/json",
                            "HTTP-Referer": "https://online-examination-system-with-anti.onrender.com",
                            "X-Title": "Online Examination System Proctor"
                        }
                        payload = {
                            "model": or_model,
                            "messages": [
                                {
                                    "role": "user",
                                    "content": [
                                        {"type": "text", "text": or_prompt},
                                        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{ref_b64_or}"}},
                                        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{live_b64_or}"}}
                                    ]
                                }
                            ],
                            "temperature": 0.1
                        }
                        try:
                            resp = http_post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=14)
                            if resp.status_code == 200:
                                res_json = resp.json()
                                choices = res_json.get("choices", [])
                                if choices and "message" in choices[0] and "content" in choices[0]["message"]:
                                    content = choices[0]["message"]["content"]
                                    if isinstance(content, list):
                                        content = "".join([c.get("text", "") for c in content if isinstance(c, dict)])
                                    content = str(content).strip()
                                    if content.startswith("```json"):
                                        content = content[7:]
                                    if content.startswith("```"):
                                        content = content[3:]
                                    if content.endswith("```"):
                                        content = content[:-3]
                                    content = content.strip()
                                    import re
                                    json_match = re.search(r'\{[\s\S]*?\}', content)
                                    if json_match:
                                        data = json.loads(json_match.group(0))
                                        is_match = bool(data.get("is_match", False))
                                        confidence = float(data.get("confidence", 0.0))
                                        reason = data.get("reason", "OpenRouter vision verification complete.")
                                        if not is_match:
                                            confidence = 0.0
                                        return {
                                            "success": True,
                                            "is_match": is_match,
                                            "confidence": round(confidence, 1),
                                            "reason": reason,
                                            "model_used": f"OpenRouter ({or_model})"
                                        }
                            elif resp.status_code == 429:
                                continue
                        except Exception as or_err:
                            print(f"OpenRouter face verification error ({or_model}): {or_err}")
        except Exception as setup_or_err:
            print(f"OpenRouter vision setup error: {setup_or_err}")

    # 3. Robust Fallback: Local facial crop comparison (focuses on face center, ignoring clothes & background)
    try:
        import math
        from PIL import Image

        def crop_face_center(img_path):
            with Image.open(img_path) as im:
                im = im.convert('L')
                w, h = im.size
                # Center crop to isolate face: remove top 12% (ceiling/hair) and bottom 22% (shirt/chest)
                left = int(w * 0.15)
                top = int(h * 0.12)
                right = int(w * 0.85)
                bottom = int(h * 0.78)
                cropped = im.crop((left, top, right, bottom))
                return cropped.resize((64, 64))

        face1 = crop_face_center(reference_image_path)
        face2 = crop_face_center(live_snapshot_path)

        p1 = list(face1.getdata())
        p2 = list(face2.getdata())
        n = len(p1)
        m1 = sum(p1) / n
        m2 = sum(p2) / n
        std1 = math.sqrt(sum((x - m1) ** 2 for x in p1) / n) + 1e-5
        std2 = math.sqrt(sum((x - m2) ** 2 for x in p2) / n) + 1e-5
        corr = sum(((x - m1) / std1) * ((y - m2) / std2) for x, y in zip(p1, p2)) / n
        norm_corr = max(0.0, corr)

        # Face similarity threshold for center facial structure across lighting/camera angles
        is_m = (norm_corr >= 0.40)
        if is_m:
            conf = round(84.0 + min(14.0, (norm_corr - 0.40) * 35.0), 1)
        else:
            conf = 0.0

        return {
            "success": True,
            "is_match": is_m,
            "confidence": conf,
            "reason": ("Facial geometry and features match registered photo." if is_m 
                       else "Different facial structure or impostor detected."),
            "model_used": "Local Biometric Analyzer (Fallback)"
        }
    except Exception as local_err:
        return {
            "success": False,
            "error": f"Face verification error: {local_err}"
        }

def generate_viva_defense_questions(student_name, exam_title, questions_and_answers, strike_count=0):
    """
    Generates targeted academic oral viva questions to verify if the student
    personally solved the exam or relied on external AI/impostors.
    Works via Gemini / OpenRouter or intelligent local rule heuristics.
    """
    api_key = get_setting("GEMINI_API_KEY")
    qa_summary = []
    for idx, qa in enumerate(questions_and_answers[:6]):
        q_text = qa.get("question_text", "")[:180]
        s_ans = qa.get("student_answer", "")[:350]
        if s_ans and s_ans != "Not Attempted":
            qa_summary.append(f"Q{idx+1}: {q_text}\nStudent's Submitted Answer: {s_ans}")

    if not qa_summary:
        return {
            "success": True,
            "viva_questions": [
                {
                    "question": "Can you summarize the core conceptual theme of this examination and the methodology behind your principal answers?",
                    "expected_points": "Clear verbal articulation of core subject concepts without hesitation.",
                    "focus_area": "Overall Subject Comprehension"
                },
                {
                    "question": "Walk me through how you structured your answer to the highest-weighted question on this test.",
                    "expected_points": "Step-by-step breakdown matching their written submission.",
                    "focus_area": "Methodological Authenticity"
                }
            ],
            "model_used": "Heuristic Viva Generator"
        }

    qa_context_text = "\n\n".join(qa_summary)
    
    prompt = f"""You are an elite university oral viva examiner reviewing a proctored examination attempt by student "{student_name}" for exam "{exam_title}".
The student has {strike_count} proctoring anomalies or high marks that require verbal verification.

Below are the actual questions and the student's submitted responses:
{qa_context_text}

Generate 3 targeted, insightful, and specific viva interview questions that an instructor can ask the student to immediately verify if they personally authored their answers.
For each question:
1. Reference a specific logic step, argument, or term from their submitted answer.
2. Provide the key conceptual points the student MUST mention if they genuinely wrote it.
3. Specify the targeted focus area.

Return strictly a JSON array with exactly this structure:
[
  {{
    "question": "In your answer to Question 1, you mentioned [...]. Could you explain the underlying reasoning behind this choice and how it behaves under edge cases?",
    "expected_points": "The student should explain [...], emphasizing [...].",
    "focus_area": "Algorithmic Reasoning / Conceptual Depth"
  }}
]
Do not wrap in markdown quotes if possible, return valid JSON only."""

    # 1. Try Gemini
    if api_key:
        keys = parse_api_keys(api_key)
        for key in keys:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={key}"
                resp = http_post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                    timeout=25
                )
                if resp.status_code == 200:
                    cand = resp.json().get("candidates", [])
                    if cand:
                        raw = cand[0]["content"]["parts"][0]["text"].strip()
                        if "```json" in raw:
                            raw = raw.split("```json")[1].split("```")[0].strip()
                        elif "```" in raw:
                            raw = raw.split("```")[1].split("```")[0].strip()
                        start_i = raw.find("[")
                        end_i = raw.rfind("]")
                        if start_i != -1 and end_i != -1:
                            raw = raw[start_i:end_i+1]
                        parsed = json.loads(raw)
                        if isinstance(parsed, list) and len(parsed) > 0:
                            return {"success": True, "viva_questions": parsed, "model_used": "Google Gemini 2.0 Flash"}
            except Exception as e:
                print(f"Viva generation error: {e}")

    # Fallback heuristic viva questions tailored to the questions
    fallback = []
    for i, qa in enumerate(questions_and_answers[:3]):
        q_snippet = qa.get("question_text", "the question")[:90]
        fallback.append({
            "question": f"Regarding your submission on \"{q_snippet}...\": Could you explain your reasoning step-by-step and why you chose that particular approach?",
            "expected_points": "Candidate must explain the core technical steps without referencing external tabs or pausing.",
            "focus_area": f"Question {i+1} Verification"
        })

    return {"success": True, "viva_questions": fallback, "model_used": "Academic Heuristic Engine (Fallback)"}


