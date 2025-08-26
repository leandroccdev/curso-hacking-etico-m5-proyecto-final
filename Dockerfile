FROM ubuntu:noble
# INSTALAR DEPENDENCIAS
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libfuzzy-dev \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    tree \
    php \
    php-sqlite3 \
    wkhtmltopdf

# CONFIGURAR PROYECTO
ENV PYTHONWARNINGS=ignore
RUN mkdir -p /opt/flc-scanner
COPY etapa1 /opt/flc-scanner/etapa1
COPY etapa2 /opt/flc-scanner/etapa2
COPY etapa3 /opt/flc-scanner/etapa3
COPY etapa5 /opt/flc-scanner/etapa5
COPY reportes /opt/flc-scanner/reportes
# Borrado de archivos innecesarios
WORKDIR /opt/flc-scanner
RUN rm -rf etapa1/.venv \
    etapa1/.vscode \
    etapa1/log/* \
    etapa1/relevant-headers.txt \
    etapa2/.venv \
    etapa2/.vscode \
    etapa3/sqli/.venv \
    etapa3/sqli/.vscode \
    etapa3/xss/.venv \
    etapa3/xss/.vscode \
    etapa5/.venv \
    etapa5/relevant-headers.txt \
    etapa5/criterios-headers.md \
    etapa5/services.sin-traducir.json \
    etapa5/to_translate.json
# Configura ambientes python de etapas
WORKDIR /opt/flc-scanner/etapa1
RUN python3 -m venv .venv
RUN .venv/bin/pip install --upgrade pip setuptools wheel
RUN .venv/bin/pip install pycparser
RUN .venv/bin/pip install --use-pep517 -r requirements.txt
WORKDIR /opt/flc-scanner/etapa2
RUN python3 -m venv .venv
RUN .venv/bin/pip install --upgrade pip setuptools wheel
RUN .venv/bin/pip install --use-pep517 -r requirements.txt
WORKDIR /opt/flc-scanner/etapa3/sqli
RUN python3 -m venv .venv
RUN .venv/bin/pip install --upgrade pip setuptools wheel
RUN .venv/bin/pip install --use-pep517 -r requirements.txt
WORKDIR /opt/flc-scanner/etapa3/xss
RUN python3 -m venv .venv
RUN .venv/bin/pip install --upgrade pip setuptools wheel
RUN .venv/bin/pip install --use-pep517 -r requirements.txt
WORKDIR /opt/flc-scanner/etapa5
RUN python3 -m venv .venv
RUN .venv/bin/pip install --upgrade pip setuptools wheel
RUN .venv/bin/pip install --use-pep517 -r requirements.txt
# Ejecuta el generador del reporte
WORKDIR /opt/flc-scanner/etapa5
CMD [".venv/bin/python", "report_generator.py"]