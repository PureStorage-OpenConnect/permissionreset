#!/bin/bash
# Monitor system stats during permissionreset run
# Usage: [MOUNT=/mnt/fb] ./monitor.sh <output_dir> [interval_seconds]

OUTDIR="${1:-.}"
INTERVAL="${2:-1}"

mkdir -p "$OUTDIR"

echo "Monitoring to $OUTDIR every ${INTERVAL}s. Ctrl+C to stop."

# Header for CSV
echo "timestamp,cpu_user,cpu_sys,cpu_idle,mem_used_mb,mem_free_mb,nfs_ops_sec,nfs_rtt_ms,goroutines,permissionreset_rss_mb" > "$OUTDIR/stats.csv"

PREV_OPS=0
PREV_TIME=$(date +%s%N)

while true; do
    TS=$(date +%s)

    # CPU from /proc/stat
    read -r _ user nice system idle rest < /proc/stat
    TOTAL=$((user + nice + system + idle))

    # Memory
    MEM_USED=$(free -m | awk '/^Mem:/ {print $3}')
    MEM_FREE=$(free -m | awk '/^Mem:/ {print $4}')

    # NFS ops from mountstats
    NFS_LINE=$(grep -A1 "ops/s" /proc/self/mountstats 2>/dev/null | tail -1 || echo "0 0")
    NFS_OPS=$(echo "$NFS_LINE" | awk '{print $1}' 2>/dev/null || echo 0)

    # nfsiostat for RTT
    NFS_RTT=$(nfsiostat 2>/dev/null "${MOUNT:-/mnt/fb}" 2>/dev/null | grep -A1 "write:" | tail -1 | awk '{print $5}' 2>/dev/null || echo 0)

    # permissionreset process stats
    PID=$(pgrep -f "permissionreset" 2>/dev/null || pgrep -f "permissionreset" 2>/dev/null | head -1)
    if [ -n "$PID" ]; then
        RSS=$(awk '{print int($2/1024)}' /proc/$PID/statm 2>/dev/null || echo 0)
        # Page size is 4KB
        RSS=$((RSS * 4 / 1024))
        THREADS=$(ls /proc/$PID/task 2>/dev/null | wc -l)
    else
        RSS=0
        THREADS=0
    fi

    echo "$TS,$user,$system,$idle,$MEM_USED,$MEM_FREE,$NFS_OPS,$NFS_RTT,$THREADS,$RSS" >> "$OUTDIR/stats.csv"

    # Also print live
    printf "\r%s  CPU: usr=%s sys=%s  MEM: %sMB used  NFS: %s ops/s  RTT: %sms  Threads: %s  RSS: %sMB  " \
        "$(date +%H:%M:%S)" "$user" "$system" "$MEM_USED" "$NFS_OPS" "$NFS_RTT" "$THREADS" "$RSS"

    sleep "$INTERVAL"
done
