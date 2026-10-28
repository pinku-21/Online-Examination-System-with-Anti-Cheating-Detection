# ==============================================================================
# ExamGuard AI: Custom Anti-Cheating & Behavior Model Training Pipeline
# Model: YOLOv11n (Ultralytics) - Gold Standard Edge Object & Threat Detection
# ==============================================================================
# Classes:
#   0: candidate_face     (Student's real face in active frame)
#   1: second_person      (Accomplice or helper in room)
#   2: cell_phone         (Smartphones, handheld gadgets)
#   3: earphone_headset   (AirPods, Bluetooth in-ear buds, over-ear sets)
#   4: book_notes         (Physical notebooks, cheat sheets, printed paper)
#   5: background_photo   (Non-human wall posters, portraits, calendars)
# ==============================================================================

import os
import sys

def main():
    print("=" * 70)
    print("🛡️  ExamGuard AI - Custom Anti-Cheating YOLOv11 Model Training Pipeline")
    print("=" * 70)

    try:
        from ultralytics import YOLO
    except ImportError:
        print("[!] Ultralytics not installed. Install via: pip install ultralytics")
        sys.exit(1)

    import torch
    device = "0" if torch.cuda.is_available() else "cpu"
    print(f"[*] Compute Device: {device} (CUDA Available: {torch.cuda.is_available()})")

    dataset_yaml = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset.yaml")

    # Step 1: Create dataset configuration
    yaml_content = """# ExamGuard AI Custom Anti-Cheating Dataset
path: ./dataset
train: images/train
val: images/val
test: images/test

names:
  0: candidate_face
  1: second_person
  2: cell_phone
  3: earphone_headset
  4: book_notes
  5: background_photo
"""
    with open(dataset_yaml, "w") as f:
        f.write(yaml_content)
    print(f"[*] Dataset schema generated at: {dataset_yaml}")

    # Step 2: Initialize YOLOv11 Nano (Fastest and most accurate edge architecture)
    print("\n[*] Initializing YOLO11n backbone...")
    model = YOLO("yolo11n.pt")  # Auto-downloads pre-trained COCO weights

    # Step 3: Run Fine-Tuning
    print("\n[*] Launching Transfer Learning...")
    results = model.train(
        data=dataset_yaml,
        epochs=50,             # 50 epochs is standard for fine-tuning
        imgsz=640,             # Standard high-resolution webcam input
        batch=16,              # Adjust down to 8 if VRAM is constrained
        device=device,
        patience=10,           # Early stopping if mAP plateaus
        augment=True,          # Photometric & geometric augmentations (lighting, rotation)
        name="examguard_yolo11n",
        save=True,
        verbose=True
    )

    print("\n" + "=" * 70)
    print("[✓] Training Complete!")
    print(f"[*] Best weights saved at: runs/detect/examguard_yolo11n/weights/best.pt")

    # Step 4: Export to Web-Deployable Format (TensorFlow.js & ONNX)
    print("\n[*] Exporting model for browser edge execution...")
    best_weights = "runs/detect/examguard_yolo11n/weights/best.pt"
    
    if os.path.exists(best_weights):
        trained_model = YOLO(best_weights)
        
        # 1. Export to ONNX (high-speed WebAssembly / WebGPU via ONNX Runtime Web)
        print("[*] Exporting to ONNX format...")
        trained_model.export(format="onnx", half=True)
        
        # 2. Export to TensorFlow.js (for direct integration into student_exam.html)
        print("[*] Exporting to TensorFlow.js format...")
        trained_model.export(format="tfjs")
        
        print("\n[✓] Browser models exported successfully!")
        print("    -> Place exported folder in: static/models/examguard_vision/")
    else:
        print("[!] Note: Run with actual dataset images to generate exported web models.")

if __name__ == "__main__":
    main()
