#!/usr/bin/env bash

set -e

cd $(dirname $0)/../static

function extract() {
  rm -rf app
  unzip -d app artifacts.zip
  mv app/flutter_protyp/build/web/* app
  rm -rf artifacts.zip app/flutter_protyp
  echo "Successfully downloaded & extracted namib frontend"
  echo "You can access it under http://localhost:8000/app"
  exit 0
}

if [ -f artifacts.zip ]; then extract; fi

URL=https://gitlab.informatik.uni-bremen.de/api/v4/projects/namib%2fnamib-frontend/jobs/artifacts/master/download?job=web:release

if [ -z "$CI_JOB_TOKEN" ]; then
  echo "Open $URL in your browser and download the artifacts.zip into the static folder"
  read -p "Press enter to open your default browser."
  if command -v xdg-open; then xdg-open $URL
  else if command -v open; then open $URL; fi
  fi
else
  curl -Ssf --output artifacts.zip -H "JOB-TOKEN: $CI_JOB_TOKEN" "$URL"
  extract
fi

