#!/bin/bash

getnodes() {
  local n
  for i in $(find "$1" -type d -mindepth 1 -maxdepth 1 | awk -F '/' '{print $NF}'); do
    n="$i"

    if [ -d "$1/$n/node.tag" ]; then
      FIELDLIST=${n//-/ }
      FIELDLIST=${FIELDLIST//_/ }
      FIELDLIST=${FIELDLIST//\./}
      FIELD=""
      for f in $FIELDLIST; do
        f=$(echo "$f" | sed 's/^6/Six/')
        f="$(tr '[:lower:]' '[:upper:]' <<<${f:0:1})${f:1}"
        FIELD="$FIELD$f"
      done
      FIELD=$(echo "$FIELD" | sed 's/^6/Six/')
      echo "$FIELD map[string]struct{"
      getnodes "$1/$n/node.tag/"
      echo "} \`json:\"$n\"\`"
    elif [ $(find "$1/$n/" -mindepth 1 -maxdepth 1 -type d | wc -l) -gt 0 ]; then
      FIELDLIST=${n//-/ }
      FIELDLIST=${FIELDLIST//_/ }
      FIELDLIST=${FIELDLIST//\./}
      FIELD=""
      for f in $FIELDLIST; do
        f=$(echo "$f" | sed 's/^6/Six/')
        f="$(tr '[:lower:]' '[:upper:]' <<<${f:0:1})${f:1}"
        FIELD="$FIELD$f"
      done
      FIELD=$(echo "$FIELD" | sed 's/^6/Six/')
      echo "$FIELD struct {"
      getnodes "$1/$n/"
      echo "} \`json:\"$n\"\`"
    else
      FIELDLIST=${n//-/ }
      FIELDLIST=${FIELDLIST//_/ }
      FIELDLIST=${FIELDLIST//\./}
      FIELD=""
      for f in $FIELDLIST; do
        f="$(tr '[:lower:]' '[:upper:]' <<<${f:0:1})${f:1}"
        FIELD="$FIELD$f"
      done
      FIELD=$(echo "$FIELD" | sed 's/^6/Six/')
      echo "$FIELD string \`json:\"$n\"\`"
    fi
  done
}

printf "package sdk\n\n"
echo "type Config struct {"
getnodes "$1"
echo "}"
