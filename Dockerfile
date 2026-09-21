FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install --no-cache-dir -e .
# Default: run the local demo target (TEST_COINS, 127.0.0.1 inside the container).
EXPOSE 5099
CMD ["python", "-m", "tests.fixtures.demo_game.app", "--port", "5099"]
