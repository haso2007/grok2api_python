FROM python:3.10-slim

WORKDIR /app

# Add beautifulsoup4 to the list of installed packages
RUN pip install --no-cache-dir flask requests curl_cffi werkzeug loguru beautifulsoup4

VOLUME ["/data"]

COPY . .

ENV PORT=3000
EXPOSE 3000

CMD ["python", "app.py"]
