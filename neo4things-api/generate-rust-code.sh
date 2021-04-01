#!/usr/bin/env bash

set -e

rm -rf generated/src

URL=http://localhost:7000

PACKAGE_NAME=neo4things-api

APIS=(
  Thing
  Mud
)

MODELS=(
  ACL
  PaginatedACLList
  Thing
  PatchedThing
  PaginatedThingList
  Description
  Service
  PaginatedServiceList
  MUD
  PatchedMUD
  PaginatedMUDList
  UploadMud
  PaginatedUploadMudList
  MudByManufacturer
  PaginatedMudByManufacturerList
  MUDJson
  PaginatedMUDJsonList
  Generator
)

if [[ "$1" == "new" ]]; then
  curl $URL/api/schema/ | sed -e "s|paths:|servers:\n- url: $URL\npaths:|" > openapi-schema.yml
fi

./openapi-generator-cli.sh generate \
  -i openapi-schema.yml \
  -g rust \
  -o . \
  --global-property models="$(IFS=: ; echo "${MODELS[*]}")",modelDocs=false,modelTests=false,apis="$(IFS=: ; echo "${APIS[*]}")",apiTests=false,apiDocs=false,supportingFiles \
  --additional-properties packageName=$PACKAGE_NAME,supportAsync=true,library=reqwest