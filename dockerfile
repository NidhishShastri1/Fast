# Use an official Python runtime as a parent image
FROM python:3.10

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose port 8000 (FastAPI default)
EXPOSE 8000

# Start FastAPI using Uvicorn
CMD ["uvicorn", "gift:app", "--host", "0.0.0.0", "--port", "8000"]
