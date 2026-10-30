# Pinned by digest (python:3.11-slim); update deliberately
FROM python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

LABEL maintainer="LeftSize <support@leftsize.io>"
LABEL description="LeftSize Cloud Cost Optimization Scanner"

# Set working directory
WORKDIR /action

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy action files
COPY run.py stats.py ./
COPY entrypoint.sh .
COPY policies/ ./policies/

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/action/entrypoint.sh"]
