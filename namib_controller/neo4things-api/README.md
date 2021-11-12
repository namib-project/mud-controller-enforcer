# Neo4Things Service

## Start with Docker

```shell
docker-compose up
```

if you get a login error:

```shell
docker login gitlab.informatik.uni-bremen.de:5005
```

## Recreate openapi-schema

Calling the script with `new` will download the OpenAPI Spec from the neo4jthings service under  http://localhost:7000

```shell
./generate-rust-code.sh new
```
