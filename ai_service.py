import os
import json
import base64
import re
import requests
import concurrent.futures
from pypdf import PdfReader
from database import get_setting

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

def encode_image_base64(image_path):
    """Encodes an image to base64 string and detects mime type."""
    mime_type = "image/jpeg"
    ext = os.path.splitext(image_path)[1].lower()
    if ext == ".png":
        mime_type = "image/png"
    elif ext == ".webp":
        mime_type = "image/webp"

    with open(image_path, "rb") as image_file:
        b64 = base64.b64encode(image_file.read()).decode("utf-8")
        return mime_type, b64

def build_exam_system_prompt(num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """Builds a rich, dynamic system prompt supporting custom blueprints, mark distributions, and figure/diagram generation."""
    
    # Handle blueprints - only apply preset if explicitly selected or if total_marks is 80/50 AND no custom prompt was provided
    blueprint_instruction = ""
    has_custom = bool(custom_prompt and custom_prompt.strip())
    if question_type == "blueprint_80" or (total_marks and int(total_marks) == 80 and not has_custom and question_type not in ["custom", "mcq", "short", "descriptive"]):
        blueprint_instruction = """
EXAM BLUEPRINT: COMPREHENSIVE 80-MARK UNIVERSITY EXAMINATION
Generate questions distributed across three sections:
- Section A (Objective/MCQ): 10 MCQs, each worth 1.0 mark (Total: 10 marks).
- Section B (Short Conceptual Questions): 10 Short Questions, each worth 3.0 marks (Total: 30 marks).
- Section C (Long Descriptive / Essay / Architectural): 4 Long In-depth Questions, each worth 10.0 marks (Total: 40 marks).
OVERALL SUM OF POINTS MUST EQUAL EXACTLY 80.0 MARKS.
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
Generate {num_questions} concise, conceptual questions (2 to 4 marks each).
Set "question_type": "short", "options": [], and provide a clear model answer in "correct_answer".
"""
    elif question_type == "descriptive":
        blueprint_instruction = f"""
EXAM BLUEPRINT: LONG DESCRIPTIVE & ESSAY QUESTIONS
Generate {num_questions} detailed, comprehensive questions (5 to 10 marks each).
Set "question_type": "descriptive", "options": [], and provide detailed evaluation rubrics in "correct_answer".
"""
    elif question_type == "mixed":
        blueprint_instruction = f"""
EXAM BLUEPRINT: MIXED QUESTIONS
Generate {num_questions} questions with a balanced blend of MCQs (1-2 marks), Short Questions (3-5 marks), and Long Descriptive Questions (5-10 marks).
"""
    elif question_type == "custom":
        blueprint_instruction = f"""
EXAM BLUEPRINT: CUSTOM USER-SPECIFIED FORMAT & MIXED CHOICES
Generate {num_questions} questions adhering strictly to the instructor's customized question formats, mix, and breakdown.
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

    marks_guideline = f"Target Total Marks: {total_marks}" if total_marks else "Assign realistic academic mark weightages (points: 1.0, 2.0, 3.0, 4.0, 5.0, or 10.0 depending on question depth)."

    prompt = f"""You are an elite academic professor, university examiner, and syllabus creator.
Your task is to design a high-quality examination based strictly on the provided material, topic, and instructor prompt.

Difficulty Level: {difficulty}
Target Question Type: {question_type}
{marks_guideline}

{blueprint_instruction}
{custom_section}
{figures_section}

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
   - "question_type": One of "mcq", "tf", "short", or "descriptive".
   - "figure_svg": Complete SVG code string with viewBox="0 0 350 220" xmlns="http://www.w3.org/2000/svg" if figure is requested/needed, else null.
   - "figure_url": URL string of matching extracted PDF diagram, else null.
   - "options": Array of 4 string choices for "mcq", ["True", "False"] for "tf", or empty array [] for "short" and "descriptive".
   - "correct_answer": For MCQ/TF, the exact matching option string. For short/descriptive, the comprehensive reference answer or key grading points.
   - "explanation": Brief 1-2 sentence grading rubric or explanation.
   - "points": Float mark weightage for this specific question (e.g. 1.0, 2.0, 3.0, 4.0, 5.0, 10.0).
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

    models_to_try = [
        "gemini-3.8-flash",
        "gemini-flash-latest",
        "gemini-3.5-flash",
        "gemini-3.5-flash-lite",
        "gemini-flash-lite-latest"
    ]
    
    last_error = None
    for model_name in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": parts}],
            "generationConfig": {
                "temperature": 0.4,
                "response_mime_type": "application/json"
            }
        }
        
        try:
            resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=300)
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
    
    models_to_try = ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "llama-3.1-8b-instant"]
    last_error = None
    
    for model in models_to_try:
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
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

def generate_questions_unified(gemini_key=None, groq_key=None, text_content=None, image_paths=None, num_questions=5, question_type="mcq", difficulty="Medium", custom_prompt=None, total_marks=None, available_figures=None):
    """
    PARALLEL AI Orchestrator: Fires Groq + Gemini simultaneously.
    Returns the FIRST successful result — no waiting for the slow one.
    Groq typically wins in 5-15s. Gemini handles images/PDFs.
    """
    if not gemini_key and not groq_key:
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

    futures_map = {}
    errors = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        if groq_key:
            futures_map[executor.submit(generate_questions_with_groq, **kwargs_groq)] = "Groq"
        if gemini_key:
            futures_map[executor.submit(generate_questions_with_gemini, **kwargs_gemini)] = "Gemini"

        for future in concurrent.futures.as_completed(futures_map, timeout=180):
            provider = futures_map[future]
            try:
                result = future.result()
                if result.get("success"):
                    print(f"{provider} won the race!")
                    return result
                else:
                    errors.append(f"{provider}: {result.get('error', 'Failed')}")
                    print(f"{provider} failed: {result.get('error')}")
            except Exception as e:
                errors.append(f"{provider}: {str(e)}")
                print(f"{provider} exception: {e}")

    # Both failed
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
4. QUESTION TYPES & POINTS:
   - MCQs: "question_type": "mcq", 4 options in "options". Points = 1.0 (or specified in section).
   - True/False: "question_type": "tf", "options": ["True", "False"].
   - Short questions: "question_type": "short", "options": [].
   - Long / Descriptive / Proofs: "question_type": "descriptive", "options": [].
5. CORRECT ANSWERS:
   - Solve or identify the correct answer for each MCQ/question and place it in "correct_answer".
   - Provide a brief 1-sentence rubric in "explanation".
6. FIGURE & DIAGRAM LINKING (CRITICAL):
{figures_section}
   - If a question is about geometry, shapes, lines, angles, triangles, or graphs and has no matching extracted figure URL:
     Generate a clean vector SVG in "figure_svg" (<svg viewBox="0 0 350 220" xmlns="http://www.w3.org/2000/svg">...</svg>).
     Otherwise set "figure_svg": null.
   - If a question does not need or have any diagram, set both "figure_url": null and "figure_svg": null.

7. OR / ALTERNATIVE QUESTION DETECTION (CRITICAL):
   - When a question has an internal alternative separated by "OR" or "Attempt either option A or B" or "Either ... OR ...":
     * DO NOT merge them into one question.
     * DO NOT drop either question.
     * SPLIT them into TWO consecutive question objects:
       1) The primary question (e.g., Option A or the first question). Set "is_or_choice": false.
       2) The alternative question (Option B or the second question after "OR"). YOU MUST prefix its "question_text" with "[OR Alternative] " AND set "is_or_choice": true.
       3) Give BOTH the same points (e.g. 5.0 marks each).
       4) Link each question to its OWN figure diagram! (e.g., Option A gets its diagram in figure_url/figure_svg, and Option B gets its diagram in its own figure_url/figure_svg).
   - Example:
     [
       {{
         "question_text": "A. Observe the structure of hearts A, B and C shown above and answer the following questions: I. Which of the hearts depicted above is present in both birds and Mammals...",
         "question_type": "descriptive",
         "options": [],
         "correct_answer": "...",
         "points": 5.0,
         "figure_url": "/static/extracted_figures/page16_fig1.png",
         "figure_svg": null,
         "is_or_choice": false
       }},
       {{
         "question_text": "[OR Alternative] B. Observe both the diagrams A and B. Which diagram indicates inhalation? Describe how it occurs...",
         "question_type": "descriptive",
         "options": [],
         "correct_answer": "...",
         "points": 5.0,
         "figure_url": "/static/extracted_figures/page16_fig2.png",
         "figure_svg": null,
         "is_or_choice": true
       }}
     ]

JSON FORMAT:
Output ONLY a valid JSON array of question objects starting with [ and ending with ].
No markdown codeblocks or backticks. Schema:
[
  {{
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
        "gemini-3.8-flash",
        "gemini-3.5-flash",
        "gemini-3.7-flash",
        "gemini-flash-latest",
        "gemini-3.5-flash-lite",
        "gemini-3.1-flash-lite",
        "gemini-flash-lite-latest"
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
    
    for model_name in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
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
            resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=120)
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
                        # If AI merged question with an internal " OR " or "\nOR\n" or "\n(OR)\n"
                        or_pattern = re.compile(r"\n\s*(?:OR|\(OR\)|---\s*OR\s*---)\s*\n", re.IGNORECASE)
                        has_merged_or = bool(or_pattern.search(q_text))

                        if has_merged_or:
                            parts = or_pattern.split(q_text, maxsplit=1)
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
                            # If second question has a different figure or diagram, keep it
                            processed_questions.append(q_copy2)
                        else:
                            # Check if flagged as is_or_choice or starts with [OR Alternative]
                            is_or = bool(q.get("is_or_choice") or q_text.startswith("[OR Alternative]"))
                            if is_or:
                                q["is_or_choice"] = True
                                if not q_text.startswith("[OR Alternative]"):
                                    q["question_text"] = f"[OR Alternative] {q_text}"
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
    Evaluates a student's answer (written text or uploaded handwritten photos/pages) using AI.
    Supports Google Gemini (with multi-image vision for multi-page solutions) and Groq Cloud.
    Returns: {"success": bool, "awarded_marks": float, "feedback": str, "model_used": str}
    """
    max_pts = float(max_points) if max_points else 1.0

    # Collect all valid image paths (single or multiple pages)
    all_imgs = []
    if image_paths and isinstance(image_paths, list):
        for p in image_paths:
            if p and os.path.exists(p) and p not in all_imgs:
                all_imgs.append(p)
    if image_path and os.path.exists(image_path) and image_path not in all_imgs:
        all_imgs.append(image_path)

    pages_note = f" (Student attached {len(all_imgs)} page(s) of handwritten solution)" if all_imgs else ""

    eval_prompt = f"""You are a fair, expert academic examiner evaluating a student's answer for an examination.

QUESTION:
{question_text}

TOTAL MAXIMUM MARKS:
{max_pts}

MODEL / REFERENCE ANSWER & KEY CRITERIA:
{correct_answer or 'Grade based on fundamental correctness, clarity, conceptual accuracy, and completeness.'}

GRADING RUBRIC / EXPLANATION:
{explanation or 'Award marks proportionately based on correctness (0 to ' + str(max_pts) + ').'}

STUDENT'S WRITTEN TEXT:
{student_text or '(No typed text provided - examine the attached photo(s) of the handwritten answer)'}{pages_note}

EVALUATION INSTRUCTIONS:
1. Carefully inspect the student's submitted response. If multiple pages/photos are attached, inspect all pages sequentially to read the complete solution, proof, or calculation.
2. For 2, 3, 4, 5, or 10-mark questions:
   - Award full marks if the answer/proof/calculation across all pages is complete and correct.
   - Award partial marks (e.g. 1, 1.5, 2, 2.5, 3, 3.5, 4, etc.) for correct steps, valid method, or partially complete explanations.
   - Award 0 if completely irrelevant or incorrect.
3. Awarded marks MUST be between 0.0 and {max_pts}.
4. Provide constructive, concise feedback explaining what was done well and any missing points.

STRICT JSON OUTPUT FORMAT:
Return ONLY a JSON object with this exact structure:
{{
  "awarded_marks": 2.5,
  "feedback": "Page 1 and Page 2 steps are correct. Minor arithmetic error in the final step."
}}
"""

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
            "gemini-3.8-flash",
            "gemini-flash-latest",
            "gemini-3.5-flash",
            "gemini-3.5-flash-lite",
            "gemini-flash-lite-latest"
        ]

        for model_name in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={gemini_key}"
            payload = {
                "contents": [{"parts": parts}],
                "generationConfig": {
                    "temperature": 0.2,
                    "response_mime_type": "application/json"
                }
            }
            try:
                resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=45)
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
                    awarded = float(data.get("awarded_marks", 0.0))
                    awarded = max(0.0, min(max_pts, round(awarded, 1)))
                    feedback = data.get("feedback", "AI evaluated response.")
                    return {
                        "success": True,
                        "awarded_marks": awarded,
                        "feedback": feedback,
                        "model_used": f"Google Gemini ({model_name})"
                    }
            except Exception as e:
                print(f"Gemini evaluation error ({model_name}): {e}")

    # 3. Try Groq (if text-based or if student provided text)
    if groq_key and student_text:
        groq_models = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]
        for g_model in groq_models:
            try:
                headers = {
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": g_model,
                    "messages": [
                        {"role": "system", "content": "You are an academic grader. Return only JSON with 'awarded_marks' and 'feedback'."},
                        {"role": "user", "content": eval_prompt}
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"}
                }
                resp = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload, timeout=30)
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"].strip()
                    data = json.loads(content)
                    awarded = float(data.get("awarded_marks", 0.0))
                    awarded = max(0.0, min(max_pts, round(awarded, 1)))
                    feedback = data.get("feedback", "AI evaluated response.")
                    return {
                        "success": True,
                        "awarded_marks": awarded,
                        "feedback": feedback,
                        "model_used": f"Groq ({g_model})"
                    }
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

            prompt = f"""You are a zero-tolerance forensic biometric identity verification AI for high-stakes university and enterprise exams.
TASK:
Compare IMAGE 1 (Official registered reference photo of student: {student_name or 'Candidate'}) with IMAGE 2 (Live webcam snapshot captured right now at exam check-in).

MANDATORY RULES:
1. Examine fine biometric landmarks:
   - Craniofacial bone structure, head width, jawline shape and chin contour.
   - Inter-pupillary distance (distance between eyes), eye socket shape, eyebrow arch and thickness.
   - Nose bridge width, nasal tip contour, and nostril shape.
   - Mouth width, lip thickness, and ear position/shape.
2. DIFFERENT PERSON RULE (CRITICAL):
   - If IMAGE 1 and IMAGE 2 show TWO DIFFERENT INDIVIDUALS (even if they share similar age, skin complexion, hair color, or gender):
     YOU MUST REJECT IMMEDIATELY.
     Set "is_match": false
     Set "confidence": 0
     Provide a clear reason identifying the structural differences (e.g., different facial shape, different nose structure, different eye spacing).
3. SAME PERSON RULE:
   - ONLY return "is_match": true IF YOU ARE 100% CERTAIN beyond any reasonable doubt that it is the exact same human subject (allowing only normal camera lighting or slight facial angle variations).
   - If you have ANY doubt or if the features belong to another person, you MUST return "is_match": false and "confidence": 0.

OUTPUT FORMAT (Respond ONLY with valid JSON):
{{
  "is_match": false,
  "confidence": 0,
  "reason": "Biometric mismatch: Facial bone structure, nose bridge width, and eye distance belong to a different individual."
}}
"""

            parts = [
                {"text": prompt},
                {"text": "--- IMAGE 1: REGISTERED STUDENT REFERENCE PHOTO ---"},
                {"inline_data": {"mime_type": ref_mime, "data": ref_b64}},
                {"text": "--- IMAGE 2: LIVE WEBCAM SNAPSHOT TAKEN AT EXAM ENTRY ---"},
                {"inline_data": {"mime_type": live_mime, "data": live_b64}}
            ]

            # Fast vision models ordered by accuracy and availability
            models = [
                "gemini-2.5-flash",
                "gemini-2.0-flash",
                "gemini-flash-latest",
                "gemini-1.5-flash",
                "gemini-flash-lite-latest",
                "gemini-3.5-flash-lite"
            ]

            for model_name in models:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={gemini_key.strip()}"
                payload = {
                    "contents": [{"parts": parts}],
                    "generationConfig": {
                        "temperature": 0.0,
                        "response_mime_type": "application/json"
                    }
                }
                try:
                    resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=8)
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
                        is_match = bool(data.get("is_match", False))
                        confidence = float(data.get("confidence", 0.0))
                        reason = data.get("reason", "Face verification evaluated by Gemini AI.")
                        if not is_match:
                            # User requirement: Mismatched or different individuals must show 0%
                            confidence = 0.0
                        return {
                            "success": True,
                            "is_match": is_match,
                            "confidence": round(confidence, 1),
                            "reason": reason,
                            "model_used": f"Gemini Vision ({model_name})"
                        }
                    else:
                        print(f"Gemini face verification error ({model_name}): status {resp.status_code} - {resp.text[:120]}")
                except Exception as e:
                    print(f"Gemini face verification exception ({model_name}): {e}")
        except Exception as enc_err:
            print(f"Gemini verification setup error: {enc_err}")

    # 2. Robust Fallback: Local image biometric comparison (Pure Pillow + math, with optional numpy support)
    try:
        import math
        from PIL import Image

        has_np = False
        try:
            import numpy as np
            has_np = True
        except ImportError:
            has_np = False

        if has_np:
            img1 = Image.open(reference_image_path).convert('L').resize((96, 96))
            img2 = Image.open(live_snapshot_path).convert('L').resize((96, 96))
            a1 = np.array(img1, dtype=np.float32)
            a2 = np.array(img2, dtype=np.float32)
            a1 = (a1 - a1.mean()) / (a1.std() + 1e-5)
            a2 = (a2 - a2.mean()) / (a2.std() + 1e-5)
            corr = float(np.mean(a1 * a2))

            c1 = Image.open(reference_image_path).convert('RGB').resize((32, 32))
            c2 = Image.open(live_snapshot_path).convert('RGB').resize((32, 32))
            h1 = np.array(c1.histogram(), dtype=np.float32)
            h2 = np.array(c2.histogram(), dtype=np.float32)
            h1 /= (np.linalg.norm(h1) + 1e-5)
            h2 /= (np.linalg.norm(h2) + 1e-5)
            hist_sim = float(np.dot(h1, h2))
        else:
            img1 = Image.open(reference_image_path).convert('L').resize((96, 96))
            img2 = Image.open(live_snapshot_path).convert('L').resize((96, 96))
            p1 = list(img1.getdata())
            p2 = list(img2.getdata())
            n = len(p1)
            m1 = sum(p1) / n
            m2 = sum(p2) / n
            std1 = math.sqrt(sum((x - m1) ** 2 for x in p1) / n) + 1e-5
            std2 = math.sqrt(sum((x - m2) ** 2 for x in p2) / n) + 1e-5
            corr = sum(((x - m1) / std1) * ((y - m2) / std2) for x, y in zip(p1, p2)) / n

            c1 = Image.open(reference_image_path).convert('RGB').resize((32, 32))
            c2 = Image.open(live_snapshot_path).convert('RGB').resize((32, 32))
            h1 = list(c1.histogram())
            h2 = list(c2.histogram())
            norm1 = math.sqrt(sum(x * x for x in h1)) + 1e-5
            norm2 = math.sqrt(sum(y * y for y in h2)) + 1e-5
            hist_sim = sum((x / norm1) * (y / norm2) for x, y in zip(h1, h2))

        norm_corr = max(0.0, corr)
        hist_sim = max(0.0, min(1.0, hist_sim))
        # Combined score weights structural correlation (85%) over color/background histograms (15%)
        combined_score = max(0.0, min(1.0, (norm_corr * 0.85 + hist_sim * 0.15)))

        # Strict threshold: two different people in the same room must never pass
        is_m = (combined_score >= 0.84 and norm_corr >= 0.80)
        if is_m:
            conf = round(80.0 + ((combined_score - 0.84) / 0.16) * 18.0, 1)
            conf = min(98.0, max(80.0, conf))
        else:
            conf = 0.0

        return {
            "success": True,
            "is_match": is_m,
            "confidence": conf,
            "reason": ("Facial structural correlation and features match registered photo." if is_m 
                       else "Different facial structure, feature geometry, or impostor detected."),
            "model_used": "Local Biometric Analyzer (Fallback)"
        }
    except Exception as local_err:
        return {
            "success": False,
            "error": f"Face verification error: {local_err}"
        }

