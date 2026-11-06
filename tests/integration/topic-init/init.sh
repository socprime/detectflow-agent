#!/usr/bin/env bash
# Idempotent provisioning for the 5 detectflow.* topics + the 3 pipeline
# destination topics our fixtures emit on. Runs in the apache/kafka image
# (kafka-topics.sh on PATH). The compose service waits for the broker to
# accept connections, then exits 0 once all topics are present.

set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"

echo "topic-init: waiting for broker at $BOOTSTRAP..."
for _ in $(seq 1 60); do
    if /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

create_topic() {
    local name="$1"
    local partitions="$2"
    local cleanup="$3"  # "compact" | "delete"

    if /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
            --describe --topic "$name" >/dev/null 2>&1; then
        echo "topic-init: $name already exists, skipping"
        return
    fi

    /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
        --create --topic "$name" \
        --partitions "$partitions" --replication-factor 1 \
        --config "cleanup.policy=$cleanup" \
        $( [ "$cleanup" = "compact" ] && echo "--config min.cleanable.dirty.ratio=0.01" )
    echo "topic-init: created $name (partitions=$partitions, cleanup=$cleanup)"
}

# Compacted broadcast topics.
create_topic "detectflow.active-threats" 1 "compact"
create_topic "detectflow.hos-rules"      1 "compact"
create_topic "detectflow.chains-config"  1 "compact"

# Regular event-stream topics, 12 partitions, key=chain_id.
create_topic "detectflow.chains-raw"      12 "delete"
create_topic "detectflow.chains-analysed" 12 "delete"

# Pipeline destination topics — harness names the producer writes to.
# Isolation is membership → tagged-events.<pipeline_id>, not these names.
# 2 partitions matches the matcher's parallelism (taskmanager.numberOfTaskSlots=2
# in docker-compose.yml). Without this, only 1 source subtask gets a partition
# and the other reports watermark Long.MIN forever — Pyflink+KafkaSource v2
# does not propagate `with_idleness` from a no-splits subtask, so the
# matcher's union watermark would freeze at Long.MIN and disable late-drop.
create_topic "dest-windows-events-raw"     2 "delete"
create_topic "dest-powershell-logs-raw"    2 "delete"
create_topic "dest-cloudtrail-detections"  2 "delete"

echo "topic-init: done"
