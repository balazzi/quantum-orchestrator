FROM python:3.12-slim
WORKDIR /app
COPY . /app
EXPOSE 8080
# zero dependencies — stdlib only
CMD ["python3", "run.py", "serve", "--host", "0.0.0.0", "--port", "8080"]
