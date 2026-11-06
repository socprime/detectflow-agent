#!/usr/bin/env bash
# Idempotent provisioning for the TWO-TENANT integration overlay
# (docker-compose.two-tenant.yml). The base init.sh keeps the shared names;
# this one adds the per-pipeline topic families:
# `detectflow.tagged-events.<pipeline_id>` and
# `detectflow.chains-{config,raw,analysed}.<correlation_pipeline_id>`.
#
# The two vendor catalogs stay SHARED and are created by init.sh; this
# script never touches them, which is the point — per-tenant Active-Threat
# monitoring is a deny-list on each tenant's chains-config, not a topic split.
#
# Partitions are 2 per tagged-events topic (not the cluster's 6): the matcher
# runs at parallelism 1 here and every source subtask must own a split, or its
# watermark stays at Long.MIN — see init.sh for the full rationale.

set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"

CORR_A=aaaaaaaa-0000-5000-a000-00000000000a
CORR_B=bbbbbbbb-0000-5000-b000-00000000000b
A1=a1000000-0000-5000-a000-000000000001
A2=a1000000-0000-5000-a000-000000000002
B1=b1000000-0000-5000-b000-000000000003
B2=b1000000-0000-5000-b000-000000000004

echo "topic-init-2t: waiting for broker at $BOOTSTRAP..."
for _ in $(seq 1 60); do
    if /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

create_topic() {
    local name="$1" partitions="$2" cleanup="$3"
    if /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
            --describe --topic "$name" >/dev/null 2>&1; then
        echo "topic-init-2t: $name already exists, skipping"
        return
    fi
    /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
        --create --topic "$name" \
        --partitions "$partitions" --replication-factor 1 \
        --config "cleanup.policy=$cleanup" \
        $( [ "$cleanup" = "compact" ] && echo "--config min.cleanable.dirty.ratio=0.01" )
    echo "topic-init-2t: created $name (partitions=$partitions, cleanup=$cleanup)"
}

for pid in "$A1" "$A2" "$B1" "$B2"; do
    create_topic "detectflow.tagged-events.$pid" 2 "delete"
done

for cid in "$CORR_A" "$CORR_B"; do
    create_topic "detectflow.chains-config.$cid"   1 "compact"
    create_topic "detectflow.chains-raw.$cid"      3 "delete"
    create_topic "detectflow.chains-analysed.$cid" 3 "delete"
done

echo "topic-init-2t: done"
