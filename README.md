# detective

docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock --name Grype anchore/grype:latest utrecht/n3dr:6.2.0
trivy image utrecht/n3dr:6.2.0
docker run -it anchore/syft:latest utrecht/n3dr:6.2.0

docker run -it -v $PWD/bla:/tmp/bla/ anchore/syft:latest utrecht/n3dr:6.2.0 -o template -t /tmp/bla/csv.tmpl
python3 docker_pull.py utrecht/n3dr:6.2.0

curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b blabla
./blabla/syft utrecht_n3dr.tar

trivy image --input utrecht_n3dr.tar

curl -X POST -H 'Content-Type: application/json' localhost:8888 -d '{"image":"utrecht/n3dr","tag":"6.2.0"}'

docker build --no-cache -t boo .

https://aquasecurity.github.io/trivy/v0.17.2/examples/report/

```bash
curl -X GET "localhost:1323/api/v1/scan/results?name=utrecht/n3dr&tag=6.0.3" -s| jq .critical
```

```bash
curl -X POST -H 'Content-Type: application/json' localhost:1323/api/v1/scan/metrics -d '{"name":"alpine","tag":"3.12.0"}'
```
