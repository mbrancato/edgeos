#!/bin/bash

getfieldtype() {
  if [ -f "$1/node.def" ]; then
    TYPE=$(cat "$1/node.def" | grep "^type" | cut -d ";" -f 1 | cut -d ":" -f 2 | sed 's/[[:blank:]]//g')
    case $TYPE in
    "txt")
      echo "*string \`json:\"$2,omitempty\"\`"
      ;;
    "bool")
      echo "*bool \`json:\"$2,omitempty\"\`"
      ;;
    "u32")
      echo "*int \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4")
      echo "*IPv4 \`json:\"$2,omitempty\"\`"
      ;;
    "ipv6")
      echo "*IPv6 \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4,ipv6")
      echo "*IP \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4net")
      echo "*IPv4Net \`json:\"$2,omitempty\"\`"
      ;;
    "ipv6net")
      echo "*IPv6Net \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4net,ipv6net")
      echo "*IPNet \`json:\"$2,omitempty\"\`"
      ;;
    "ipv6,ipv6net")
      echo "*IPv6Net \`json:\"$2,omitempty\"\`"
      ;;
    "macaddr")
      echo "*MacAddr \`json:\"$2,omitempty\"\`"
      ;;
    *)
      echo "*string \`json:\"$2,omitempty\"\`"
      ;;
    esac
  else
    echo "*string \`json:\"$2,omitempty\"\`"
  fi
}

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
      echo "$FIELD *map[string]struct{"
      getnodes "$1/$n/node.tag/"
      echo "} \`json:\"$n,omitempty\"\`"
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
      echo "$FIELD *struct {"
      getnodes "$1/$n/"
      echo "} \`json:\"$n,omitempty\"\`"
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
      FIELDSPEC=$(getfieldtype "$1/$n" "$n")
      echo "$FIELD $FIELDSPEC"
    fi
  done
}

printf "package sdk\n\n"
echo "type Config struct {"
getnodes "$1"
echo "}"
