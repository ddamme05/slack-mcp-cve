# Slack CVE Bot - Phase 2
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 slackbot

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bot.py .

# Switch to non-root user
USER slackbot

# Run the bot
CMD ["python", "-u", "bot.py"]
