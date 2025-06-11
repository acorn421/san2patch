FROM cruizba/ubuntu-dind

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/root/.local/bin:$PATH"

RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.10 \
    python3.10-dev \
    python3.10-venv \
    python3-pip \
    curl \
    vim \
    wget \
    git \
    build-essential \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3.10 /usr/bin/python3 && \
    ln -sf /usr/bin/python3.10 /usr/bin/python

RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

RUN poetry config virtualenvs.create true && \
    poetry config virtualenvs.in-project true

WORKDIR /app


COPY san2patch/ ./san2patch/
COPY pyproject.toml poetry.lock ./
RUN poetry install

ENV PATH="/app/.venv/bin:$PATH"

COPY benchmarks/ ./benchmarks/
COPY scripts/ ./scripts/
COPY experiments/ ./experiments/
COPY run.py ./run.py
COPY .env_example ./

RUN mkdir -p /app/logs && \
    mkdir -p /app/.aim

RUN chmod +x /app/scripts/*.sh

RUN cp .env_example .env

EXPOSE 43800

COPY README.md /README.md
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

CMD ["/bin/bash"] 