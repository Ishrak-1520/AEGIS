# Use a lightweight, official Python runtime
FROM python:3.11-slim

# Prevent Python from writing pyc files to disc and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Tell Python to look inside the 'core' folder for imports directly
ENV PYTHONPATH="/app/core"

# Copy only the requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app

# Ensure benchmark_runner is executable
RUN chmod +x benchmark_runner.py

# Set the default command to run the benchmark
ENTRYPOINT ["python", "benchmark_runner.py"]