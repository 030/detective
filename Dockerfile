FROM alpine:3.18.3

RUN apk add --no-cache \
        curl \
        git \
        go \
        python3 && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v0.92.0 && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3 && \
    adduser -D -g '' detective

ENV HOME /home/detective
ENV PATH_DETECTIVE ${HOME}/bin
ENV PATH ${PATH_DETECTIVE}:$PATH
USER detective
WORKDIR /home/detective/bin
COPY main.go go.mod go.sum ./
RUN go build && \
    curl -sSL https://install.python-poetry.org | python3 - --git https://github.com/python-poetry/poetry.git@master && \
    curl https://raw.githubusercontent.com/030/docker-drag/1-poetry/pyproject.toml -o pyproject.toml && \
    curl https://raw.githubusercontent.com/030/docker-drag/1-poetry/poetry.lock -o poetry.lock && \
    ~/.local/bin/poetry install && \
    curl https://raw.githubusercontent.com/030/docker-drag/1-poetry/docker_pull.py -o docker_pull.py
ENTRYPOINT detective
