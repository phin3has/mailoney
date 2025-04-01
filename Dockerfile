FROM python:3.11-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MAILONEY_DB_URL=sqlite:///mailoney.db

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run as non-root user for better security
RUN groupadd -r mailoney && \
    useradd -r -g mailoney mailoney && \
    chown -R mailoney:mailoney /app

USER mailoney

# Expose port
EXPOSE 25

# Run the application
ENTRYPOINT ["python", "main.py"]
