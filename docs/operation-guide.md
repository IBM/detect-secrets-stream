# Operation Guide

This documentation is intended for maintainers of Detect Secrets Stream.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Making changes to the production database](#making-changes-to-the-production-database)
- [Add database roles](#add-database-roles)
  - [Add a role for token metadata viewer](#add-a-role-for-token-metadata-viewer)
- [Kafka](#kafka)
  - [Connect to Kafka using the kafka CLI](#connect-to-kafka-using-the-kafka-cli)
  - [Increase partitions for a topic](#increase-partitions-for-a-topic)
  - [Display partition offset](#display-partition-offset)
  - [Consume or produce a message using the CLI](#consume-or-produce-a-message-using-the-cli)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Making changes to the production database

1. Before altering the production database, scale down services which may block the change, as they are continuously using this database

   ```sh
   kubectl scale --replicas=0 deployment/scan-worker
   kubectl scale --replicas=0 deployment/sqlexporter
   ```

1. Make changes to the database, such as `alter table token add column token_hash varchar;`
1. Scale services back up

   ```sh
   kubectl scale --replicas=<number_of_replicas> deployment/scan-worker
   kubectl scale --replicas=1 deployment/sqlexporter
   ```

## Add database roles

```qsql
CREATE ROLE scan_worker_role;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO scan_worker_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO scan_worker_role;
GRANT TRUNCATE ON TABLE public.vmt_report TO scan_worker_role;
```

### Add a role for token metadata viewer

```qsql
CREATE ROLE token_viewer_role WITH LOGIN;
GRANT CONNECT ON DATABASE dss TO token_viewer_role;
GRANT USAGE ON SCHEMA public TO token_viewer_role;
GRANT SELECT ON public.vmt_report TO token_viewer_role;

CREATE USER token_viewer WITH IN GROUP token_viewer_role PASSWORD [redacted]
```

## Kafka

It's recommended to use the [IBM Cloud Events Stream service](https://www.ibm.com/cloud/event-streams) to set up a Kafka queue.

### Connect to Kafka using the kafka CLI

1. Download the kafka CLI from <https://kafka.apache.org/downloads>
1. Extract the downloaded package into a local directory
1. Obtain the configuration and Bootstrap server
    1. If using IBM Cloud Events Stream, go to the IBM Cloud account, event stream instance page, click `Launch Dashboard` -> `Consumer groups`, then click `Connect to this service` on the top right
    1. `Connect a client` -> `Bootstrap server`
    1. `Sample code` -> `Sample configuration properties`. Copy the configuration.
1. Obtain an API key
    1. From the IBM Cloud account, locate the Events Stream resource from the resources list, and click on it
    1. On the left pane, click `Service credentials` -> `New credential`
    1. Once created, click on the newly created credential, then `View Credentials`, copy the `apikey` field from the JSON output
1. Go to your local directory and create an admin config file (`config/admin.properties`) and paste the previously copied configuration into it
1. Test that the CLI works properly by listing all topics in the queue with `bin/kafka-topics.sh --bootstrap-server <bootstrap-server> --command-config config/admin.properties --list`
    1. (Optional) Set `KAFKA_HEAP_OPTS="-Xms512m -Xmx1g"` if the JVM runs out of memory when connecting to Kafka
    1. (Optional) Update `config/tools-log4j.properties` to change the log level

### Increase partitions for a topic

1. Follow the steps in [Connect to Kafka using kafka CLI](#connect-to-kafka-using-the-kafka-cli) to set up the CLI
1. `bin/kafka-topics.sh --bootstrap-server <bootstrap-server> --command-config config/admin.properties --alter --topic <topic_name> --partitions <new_partition_count>`
    1. You can only increase the partition count

### Display partition offset

1. Follow the steps in [Connect to Kafka using kafka CLI](#connect-to-kafka-using-the-kafka-cli) to set up the CLI
1. `bin/kafka-consumer-groups.sh --bootstrap-server <bootstrap-server> --command-config config/admin.properties --group <consumer_group_name> --describe --offsets`
    1. The offset is based on the consumer group. Each consumer group will have a different offset.

### Consume or produce a message using the CLI

1. Follow the steps in [Connect to Kafka using kafka CLI](#connect-to-kafka-using-the-kafka-cli) to set up the CLI
    1. For consuming messages: instead of creating `config/admin.properties`, create `config/consumer.properties`. Then use `bin/kafka-console-consumer.sh`.
    1. For producing messages: instead of creating `config/admin.properties`, create `config/producer.properties`. Then use `bin/kafka-console-producer.sh`.
