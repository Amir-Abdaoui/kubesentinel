FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app/src KS_MODEL=/app/model/model.joblib
RUN useradd -u 10001 -m ks
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir flask gunicorn numpy scikit-learn joblib kubernetes
COPY src ./src
COPY model/ ./model/
# Bootstrap model from simulated baseline (kept outside /app/data so volumes don't hide it)
RUN mkdir -p data evidence model && ([ -f model/model.joblib ] || python -m kubesentinel train --source sim) && chown -R ks /app
USER 10001
EXPOSE 8080
CMD ["gunicorn","-b","0.0.0.0:8080","-w","1","--threads","8","--keep-alive","75","--timeout","120","kubesentinel.api:create_app()"]
