FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV DATABASE_URL=sqlite:///./data/heart_non_pro.db
ENV AVATAR_DIRECTORY=./data/avatars
ENV COOKIE_SECURE=true
ENV COOKIE_SAMESITE=none

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
