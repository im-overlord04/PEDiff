#!/bin/bash

OUTPUT=""
MODE=""
EXE1=""
EXE2=""
DIR=""
PROCESSES=1
MAIN_ONLY=false
PRINT=false

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -o|--output)
      OUTPUT="$2"
      OUTPUT_BASENAME=$(basename "$OUTPUT")
      OUTPUT_DIR=$(dirname "$OUTPUT")
      shift 2
      ;;
    -f|--files)
      MODE="files"
      EXE1="$2"
      EXE2="$3"
      EXE1_BASENAME=$(basename "$EXE1")
      EXE2_BASENAME=$(basename "$EXE2")
      shift 3
      ;;
    -d|--directory)
      MODE="directory"
      DIR="$2"
      shift 2
      ;;
    -p|--processes)
      PROCESSES="$2"
      shift 2
      ;;
    --main-only)
      MAIN_ONLY=true
      shift
      ;;
    --print)
      PRINT=true
      shift
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

CMD=(docker run -v)

if [[ $MODE == "files" ]]; then
  CMD+=("$EXE1:/$EXE1_BASENAME -v $EXE2:/$EXE2_BASENAME -v $OUTPUT_DIR:/tmp pediff -f /$EXE1_BASENAME /$EXE2_BASENAME -o /tmp/$OUTPUT_BASENAME")
elif [[ $MODE == "directory" ]]; then
  CMD+=("$DIR:/input -v $OUTPUT_DIR:/tmp pediff -d input -o /tmp/$OUTPUT_BASENAME -p $PROCESSES")
fi

$MAIN_ONLY && CMD+=(--main-only)
$PRINT && CMD+=(--print)

CMD_STRING="${CMD[*]}"
# echo "$CMD_STRING"
eval $CMD_STRING