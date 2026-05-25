#!/usr/bin/env bash
set -euo pipefail

LOG_PATH="./suricata_logs/eve.json"
RATE=1000
DURATION_SEC=60
DEST_IP="192.168.41.136"
SOURCE_PREFIX="10.10.10"
SOURCE_COUNT=32
SEVERITY=1
TRUNCATE=0

usage() {
  cat <<'USAGE'
DASRS eve.json stress writer

Usage:
  bash scripts/stress_eve_writer.sh [options]

Options:
  --log PATH              eve.json path. Default: ./suricata_logs/eve.json
  --rate N                Events written per second. Default: 1000
  --duration N            Test duration in seconds. Default: 60
  --dest-ip IP            Destination/monitored IP. Default: 192.168.41.136
  --source-prefix PREFIX  Source IP first three octets. Default: 10.10.10
  --source-count N        Number of source IPs in pool, 1-254. Default: 32
  --severity N            Suricata severity, 1 high, 2 medium, 3 low. Default: 1
  --truncate              Empty the log file before writing
  -h, --help              Show this help

Example:
  bash scripts/stress_eve_writer.sh --rate 1000 --duration 60 --dest-ip 192.168.41.136 --truncate
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log)
      LOG_PATH="$2"
      shift 2
      ;;
    --rate)
      RATE="$2"
      shift 2
      ;;
    --duration)
      DURATION_SEC="$2"
      shift 2
      ;;
    --dest-ip)
      DEST_IP="$2"
      shift 2
      ;;
    --source-prefix)
      SOURCE_PREFIX="$2"
      shift 2
      ;;
    --source-count)
      SOURCE_COUNT="$2"
      shift 2
      ;;
    --severity)
      SEVERITY="$2"
      shift 2
      ;;
    --truncate)
      TRUNCATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! [[ "$RATE" =~ ^[0-9]+$ ]] || [[ "$RATE" -le 0 ]]; then
  echo "--rate must be a positive integer" >&2
  exit 2
fi
if ! [[ "$DURATION_SEC" =~ ^[0-9]+$ ]] || [[ "$DURATION_SEC" -le 0 ]]; then
  echo "--duration must be a positive integer" >&2
  exit 2
fi
if ! [[ "$SOURCE_COUNT" =~ ^[0-9]+$ ]] || [[ "$SOURCE_COUNT" -le 0 || "$SOURCE_COUNT" -gt 254 ]]; then
  echo "--source-count must be between 1 and 254" >&2
  exit 2
fi
if ! [[ "$SEVERITY" =~ ^[123]$ ]]; then
  echo "--severity must be 1, 2, or 3" >&2
  exit 2
fi

mkdir -p "$(dirname "$LOG_PATH")"
if [[ "$TRUNCATE" -eq 1 ]]; then
  : > "$LOG_PATH"
else
  touch "$LOG_PATH"
fi

payloads=(
  "GET /search?id=1%20union%20select%201,2,3 HTTP/1.1"
  "GET /index.php?file=../../../../etc/passwd HTTP/1.1"
  "POST /login HTTP/1.1 username=admin&password=' or '1'='1"
  "GET /cgi-bin/test.sh?cmd=cat%20/etc/passwd HTTP/1.1"
)

signatures=(
  "DASRS STRESS SQL Injection Attempt"
  "DASRS STRESS Path Traversal Attempt"
  "DASRS STRESS Weak Password Probe"
  "DASRS STRESS Command Injection Probe"
)

total_target=$((RATE * DURATION_SEC))

echo "DASRS eve.json stress writer"
echo "Log path    : $LOG_PATH"
echo "Rate        : $RATE events/sec"
echo "Duration    : $DURATION_SEC sec"
echo "Total target: $total_target events"
echo "Dest IP     : $DEST_IP"
echo "Source pool : ${SOURCE_PREFIX}.1-${SOURCE_PREFIX}.${SOURCE_COUNT}"
echo

start_ns="$(date +%s%N)"
written=0

for ((second = 0; second < DURATION_SEC; second++)); do
  second_start_ns="$(date +%s%N)"
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%NZ")"

  {
    for ((i = 0; i < RATE; i++)); do
      seq=$((written + 1))
      src_octet=$(( ((seq - 1) % SOURCE_COUNT) + 1 ))
      src_ip="${SOURCE_PREFIX}.${src_octet}"
      idx=$(( (seq - 1) % ${#payloads[@]} ))
      sid=$((9100000 + idx))
      src_port=$((40000 + (seq % 20000)))

      printf '{"timestamp":"%s","event_type":"alert","src_ip":"%s","src_port":%d,"dest_ip":"%s","dest_port":80,"proto":"TCP","alert":{"signature_id":%d,"signature":"%s","category":"Attempted Administrator Privilege Gain","severity":%d},"payload_printable":"%s"}\n' \
        "$timestamp" "$src_ip" "$src_port" "$DEST_IP" "$sid" "${signatures[$idx]}" "$SEVERITY" "${payloads[$idx]}"

      written=$((written + 1))
    done
  } >> "$LOG_PATH"

  target_elapsed_ns=$(( (second + 1) * 1000000000 ))
  now_ns="$(date +%s%N)"
  elapsed_ns=$((now_ns - start_ns))
  if [[ "$elapsed_ns" -lt "$target_elapsed_ns" ]]; then
    sleep_ns=$((target_elapsed_ns - elapsed_ns))
    sleep "$(awk -v ns="$sleep_ns" 'BEGIN { printf "%.6f", ns / 1000000000 }')"
  fi

  second_end_ns="$(date +%s%N)"
  second_elapsed_ns=$((second_end_ns - second_start_ns))
  actual_rate="$(awk -v r="$RATE" -v ns="$second_elapsed_ns" 'BEGIN { if (ns <= 0) ns = 1; printf "%.2f", r * 1000000000 / ns }')"
  printf '[%3d/%3ds] wrote %d events, actual second rate %s/s\n' "$((second + 1))" "$DURATION_SEC" "$written" "$actual_rate"
done

end_ns="$(date +%s%N)"
elapsed_ns=$((end_ns - start_ns))
avg_rate="$(awk -v w="$written" -v ns="$elapsed_ns" 'BEGIN { if (ns <= 0) ns = 1; printf "%.2f", w * 1000000000 / ns }')"
elapsed_sec="$(awk -v ns="$elapsed_ns" 'BEGIN { printf "%.3f", ns / 1000000000 }')"

echo
echo "Stress write finished."
echo "Events written : $written"
echo "Elapsed seconds: $elapsed_sec"
echo "Average rate   : $avg_rate events/sec"
echo
echo "Suggested thesis wording:"
echo "The stress script generated $written Suricata alert events by appending to eve.json at $RATE events/sec for $DURATION_SEC seconds. Use this to verify Agent ingestion throughput and Master scoring latency."
