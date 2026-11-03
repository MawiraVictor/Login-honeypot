FROM python:3.12-slim
RUN useradd --create-home honeypot
WORKDIR /app
COPY src/ ./src/
RUN mkdir logs && chown honeypot:honeypot logs
USER honeypot
EXPOSE 2323 8080
CMD ["python", "src/honeypot.py", "--host", "0.0.0.0", "--log", "logs/events.jsonl"]
