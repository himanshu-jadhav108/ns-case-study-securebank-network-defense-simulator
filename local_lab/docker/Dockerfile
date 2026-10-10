# OPTIONAL isolated lab image (NOT required; base prototype runs without Docker).
FROM python:3.12-slim
WORKDIR /lab
COPY src ./src
COPY data ./data
COPY local_lab ./local_lab
ENV LAB_CONTAINER=1
EXPOSE 8080
CMD ["python", "local_lab/banking_service.py", "--host", "0.0.0.0", "--port", "8080"]
