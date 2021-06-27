# Operation Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Making prod DB change](#making-prod-db-change)
- [Add DB roles](#add-db-roles)
  - [Add role for VMT](#add-role-for-vmt)
- [Connect to DB with short lived password](#connect-to-db-with-short-lived-password)
- [Permission adjustment after adding new sequence / table](#permission-adjustment-after-adding-new-sequence--table)
- [Connect to Jaeger UI](#connect-to-jaeger-ui)
- [Manage cert with IBM CA](#manage-cert-with-ibm-ca)
  - [Request cert](#request-cert)
  - [Refresh cert](#refresh-cert)
- [Kafka](#kafka)
  - [Connect to Kafka using kafka CLI](#connect-to-kafka-using-kafka-cli)
  - [Increase partitions for a topic](#increase-partitions-for-a-topic)
  - [Display partition offset](#display-partition-offset)
  - [Consume or produce message using CLI](#consume-or-produce-message-using-cli)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Making a production database change

1. Before altering the production database, scale down services which may block the change as they are continuously using this database.

    ```sh
    kubectl scale --replicas=0 deployment/scan-worker 
    kubectl scale --replicas=0 deployment/sqlexporter 
    ```

1. Make a database change, such as `alter table token add column token_hash varchar;`
1. Scale the services back up

    ```sh
    kubectl scale --replicas=12 deployment/scan-worker 
    kubectl scale --replicas=1 deployment/sqlexporter 
    ```

## Kafka

We use event stream service from IBM Cloud. The instance is named `gd-event-streams`

### Connect to Kafka using kafka CLI

1. Download kafka CLI from <https://kafka.apache.org/downloads>
1. Extract the downloaded package into a local directory
1. Obtain configuration and Bootstrap server
    1. Go to IBM Cloud account, event stream instance page, click `Launch Dashboard` -> `Consumer groups`, then click `Connect to this service` at right top
    1. `Connect a client` -> `Bootstrap server`
    1. `Sample code` -> `Sample configuration properties`. copy the configuration.
1. Obtain an API key
    1. In IBM Cloud account, locate `gd-event-streams` from resource list, click on it
    1. Left pane, click `Service credentials` -> `New credential`
    1. Once created, click on the newly created credential, then `View Credentials`, copy the `apikey` field from json output
1. Go to local directory and create a admin config file `config/admin.properties` and paste previously copied configuration into it
1. Test the CLI is working properly by listing all topics with `bin/kafka-topics.sh --bootstrap-server <bootstrap-server> --command-config config/admin.properties --list`
    1. (Optional) Set `KAFKA_HEAP_OPTS="-Xms512m -Xmx1g"` if JVM runs into OOM when connecting Kafka
    1. (Optional) Update `config/tools-log4j.properties` to change the log level

### Increase partitions for a topic

1. Follow steps in [Connect to Kafka using kafka CLI](#connect-to-kafka-using-kafka-cli) to setup CLI
1. `bin/kafka-topics.sh --bootstrap-server <bootstrap-server> --command-config config/admin.properties --alter --topic <topic_name> --partitions <new_partition_count>`
    1. You can only increase partition count
    1. The increase action can be done online

### Display partition offset

1. Follow steps in [Connect to Kafka using kafka CLI](#connect-to-kafka-using-kafka-cli) to setup CLI
1. `bin/kafka-consumer-groups.sh --bootstrap-server <bootstrap-server> --command-config config/admin.properties --group <consumer_group_name> --describe --offsets`
    1. The offset is based on consumer group. Each consumer group would have different offset.

### Consume or produce message using CLI

1. Follow steps in [Connect to Kafka using kafka CLI](#connect-to-kafka-using-kafka-cli) to setup CLI
    1. For consume, instead of creating `config/admin.properties`, create `config/consumer.properties`. Then use `bin/kafka-console-consumer.sh`
    1. For produce, Instead of creating `config/admin.properties`, create `config/producer.properties`. Then use `bin/kafka-console-producer.sh`
