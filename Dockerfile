FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
ENV HOST=0.0.0.0 PORT=8080 VOXELLIVE_DB_PATH=/data/voxellive-v16.sqlite3
VOLUME ["/data"]
EXPOSE 8080
CMD ["python", "/app/server.py"]
