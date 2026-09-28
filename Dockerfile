FROM python:3.12-slim
WORKDIR /AI-SEC-PLATFORM
COPY requirements.txt .
RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["/opt/venv/bin/python3", "app.py"]

