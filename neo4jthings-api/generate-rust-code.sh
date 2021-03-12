#!/usr/bin/env bash

rm -rf src/apis src/models

URL=http://localhost:7000

if [[ "$1" == "new" ]]; then
  curl $URL/api/schema/ | sed -e "s|paths:|servers:\n- url: $URL\npaths:|" > openapi-schema.yml
fi

./openapi-generator-cli.sh generate \
  -i openapi-schema.yml \
  -g rust \
  -o . \
  --global-property models="ACL:Thing:Description:PatchedThing:Service:PaginatedThingList:PaginatedServiceList:PaginatedACLList",modelDocs=false,modelTests=false,apis="Thing",apiTests=false,apiDocs=false,supportingFiles \
  --additional-properties packageName=neo4jthings-api,supportAsync=true,library=reqwest