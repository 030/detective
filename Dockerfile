FROM alpine:3.18.3

RUN apk add --no-cache \
        curl \
        git \
        python3 && \
    curl https://raw.githubusercontent.com/030/docker-drag/1-poetry/docker_pull.py -o docker_pull.py && \
    curl https://raw.githubusercontent.com/030/docker-drag/1-poetry/poetry.lock -o poetry.lock && \
    curl https://raw.githubusercontent.com/030/docker-drag/1-poetry/pyproject.toml -o pyproject.toml && \
    curl -sSL https://install.python-poetry.org | python3 - --git https://github.com/python-poetry/poetry.git@master && \
    ~/.local/bin/poetry install && \
    ~/.local/bin/poetry run python3 docker_pull.py utrecht/n3dr:6.2.0

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b blabla && \
    ./blabla/syft utrecht_n3dr.tar

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3

COPY . .
RUN apk add go
RUN go build
ENTRYPOINT ./detective
