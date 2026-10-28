# 🎓 ExamGuard AI: Custom Model Training & Deployment Guide

This guide walks you through training the **YOLOv11n** model specifically for **ExamGuard AI**.

---

## 1. Quick Setup (Google Colab - Recommended for Free GPU)

Because training deep learning vision models requires an NVIDIA GPU (CUDA), the fastest, free method is **Google Colab**:

1. Open [Google Colab](https://colab.research.google.com/) and create a **New Notebook**.
2. Click **Runtime** $\rightarrow$ **Change runtime type** $\rightarrow$ select **T4 GPU** $\rightarrow$ click **Save**.
3. Install the dependencies in the first cell:
   ```bash
   !pip install ultralytics roboflow
   ```

---

## 2. Acquiring the Dataset in 1 Click

You can download ready-annotated datasets containing phones, multiple people, cheat sheets, and background objects directly:

```python
from roboflow import Roboflow

# Free public cheating detection dataset (example)
rf = Roboflow(api_key="YOUR_ROBOFLOW_API_KEY") # Or download zip directly from universe.roboflow.com
project = rf.workspace("proctoring-ai").project("exam-cheating-detection")
version = project.version(1)
dataset = version.download("yolov11")
```

Alternatively, organize your own photos into this standard folder structure:
```text
dataset/
├── images/
│   ├── train/  (70% of photos)
│   ├── val/    (20% of photos)
│   └── test/   (10% of photos)
└── labels/
    ├── train/  (.txt bounding box files)
    ├── val/
    └── test/
```

---

## 3. Launching the Training Script

Run the automated script created in your repository:
```bash
python train_proctor_model.py
```

### What Happens During Training:
- It fine-tunes **YOLOv11 Nano** over 50 epochs using pre-trained weights.
- It applies random lighting, rotations, and blur to simulate student webcams in low light.
- It automatically evaluates the model on the validation split and saves the best model to:
  ```text
  runs/detect/examguard_yolo11n/weights/best.pt
  ```

---

## 4. Exporting Directly to Your Web Application

The script automatically executes the conversion:
```python
from ultralytics import YOLO

model = YOLO("runs/detect/examguard_yolo11n/weights/best.pt")

# Convert to TensorFlow.js (model.json + weight binary chunks)
model.export(format="tfjs")
```

### Placing into ExamGuard AI:
1. Copy the exported folder into:
   ```text
   Online-Examination-System-with-Anti-Cheating-Detection/static/models/examguard_yolo/
   ```
2. In `templates/student_exam.html`, load your custom model directly:
   ```javascript
   const model = await tf.loadGraphModel('/static/models/examguard_yolo/model.json');
   ```

---

## 5. Imposter & Biometric Verification (ArcFace / FaceMesh)

For continuous imposter protection:
1. Student registers: Camera captures reference image $\rightarrow$ computes 512D facial embedding $\mathbf{E}_{\text{ref}}$.
2. During exam: MediaPipe FaceMesh / ArcFace extracts live embedding $\mathbf{E}_{\text{live}}$ every 15 seconds.
3. Compute cosine similarity:
   $$\text{Sim}(\mathbf{E}_{\text{ref}}, \mathbf{E}_{\text{live}}) = \frac{\mathbf{E}_{\text{ref}} \cdot \mathbf{E}_{\text{live}}}{\|\mathbf{E}_{\text{ref}}\| \|\mathbf{E}_{\text{live}}\|}$$
4. If similarity $< 0.72$, the exam flags `SEC-002: Candidate Imposter Detected` and triggers a biometric lock.
