# Heavy document evaluation environment

This tier is separate from fast PR CI. It is intended for a managed runner or
container with:

```text
LibreOffice/soffice in headless mode
PyMuPDF
python-pptx
Pillow
PaddlePaddle 3.x
PaddleOCR 3.x
an open-source Korean font package
```

The current development machine does not have LibreOffice or PaddleOCR, so
their integration is capability-gated and not claimed as locally executed.
Before promoting this environment, record the exact tested versions in the
evaluation summary and run native PPTX conversion plus actual Korean OCR.

Suggested bootstrap on Ubuntu:

```bash
apt-get update
apt-get install -y libreoffice fonts-noto-cjk
python -m pip install -e ".[pdf,pptx,ocr-paddle]"
```

Use an isolated Office profile, explicit subprocess argv, a timeout, and a
network-restricted worker. Do not run this tier with confidential material on
public GitHub-hosted runners.
