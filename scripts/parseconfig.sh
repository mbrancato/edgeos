#!/bin/bash

getfieldtype() {
  if [ -f "$1/node.def" ]; then
    TYPE=$(cat "$1/node.def" | grep "^type" | cut -d ";" -f 1 | cut -d ":" -f 2 | sed 's/[[:blank:]]//g')
    case $TYPE in
    "txt")
      echo "string \`json:\"$2,omitempty\"\`"
      ;;
    "bool")
      echo "bool \`json:\"$2,omitempty\"\`"
      ;;
    "u32")
      echo "int \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4")
      echo "IPv4 \`json:\"$2,omitempty\"\`"
      ;;
    "ipv6")
      echo "IPv6 \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4,ipv6")
      echo "IP \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4net")
      echo "IPv4Net \`json:\"$2,omitempty\"\`"
      ;;
    "ipv6net")
      echo "IPv6Net \`json:\"$2,omitempty\"\`"
      ;;
    "ipv4net,ipv6net")
      echo "IPNet \`json:\"$2,omitempty\"\`"
      ;;
    "ipv6,ipv6net")
      echo "IPv6Net \`json:\"$2,omitempty\"\`"
      ;;
    "macaddr")
      echo "MacAddr \`json:\"$2,omitempty\"\`"
      ;;
    *)
      echo "json.RawMessage \`json:\"$2,omitempty\"\`"
      ;;
    esac
  else
    echo "*string \`json:\"$2,omitempty\"\`"
  fi
}

# This creates many smaller structs instead of a large config struct to avoid
# this issue: https://github.com/golang/go/issues/18920
getnodes() {
  local n
  local HEAD=$2
  local TAIL=$3
  local PREFIX=$4
  local CHILDREN=()

  echo "$HEAD"
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
      #getnodes "$1/$n/node.tag/" "$FIELD *map[string]struct{" "} \`json:\"$n,omitempty\"\`"
      echo "$FIELD *$PREFIX$FIELD \`json:\"$n,omitempty\"\`"
      CHILDREN+=("$1/$n/node.tag/;type $PREFIX$FIELD map[string]struct{;};$PREFIX$FIELD")
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
      #getnodes "$1/$n/" "$FIELD *struct {" "} \`json:\"$n,omitempty\"\`"
      echo "$FIELD *$PREFIX$FIELD \`json:\"$n,omitempty\"\`"
      CHILDREN+=("$1/$n/;type $PREFIX$FIELD struct{;};$PREFIX$FIELD")
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
  echo "$TAIL"
  printf "\n"

  for child in "${CHILDREN[@]}"; do
    NEXTPATH=$(echo "$child" | cut -f 1 -d ';' )
    NEXTHEAD=$(echo "$child" | cut -f 2 -d ';' )
    NEXTTAIL=$(echo "$child" | cut -f 3 -d ';' )
    NEXTPREFIX=$(echo "$child" | cut -f 4 -d ';' )
    getnodes "$NEXTPATH" "$NEXTHEAD" "$NEXTTAIL" "$NEXTPREFIX"
  done

}

getfirstnodes() {
  local n

  NODES=()

  for i in $(find "$1" -type d -mindepth 1 -maxdepth 1 | awk -F '/' '{print $NF}'); do
    n="$i"

    if [ $(find "$1/$n/" -mindepth 1 -maxdepth 1 -type d | wc -l) -gt 0 ]; then
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
      NODES+=("$FIELD Config$FIELD \`json:\"$n,omitempty\"\`")
      getnodes "$1/$n/" "type Config$FIELD *struct{" "}" "Config$FIELD"
    fi
  done

  echo "type Config struct {"
  for node in "${NODES[@]}"; do
    echo "$node"
  done
  echo "}"
}

printf "package sdk\n\n"

getfirstnodes "$1"
