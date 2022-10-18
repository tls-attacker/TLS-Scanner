/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.orchestration;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import de.rub.nds.tlscrawler.config.delegate.RabbitMqDelegate;
import de.rub.nds.tlscrawler.data.ScanJob;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeoutException;

/**
 * Provides all methods required for the communication with RabbitMQ for the controller and the worker.
 */
public class RabbitMqOrchestrationProvider {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String SCAN_JOB_QUEUE = "scan-job-queue";
    private static final String DONE_NOTIFY_QUEUE = "done-notify-queue";

    private Connection connection;

    private Channel channel;

    public RabbitMqOrchestrationProvider(RabbitMqDelegate rabbitMqDelegate) {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(rabbitMqDelegate.getRabbitMqHost());
        factory.setPort(rabbitMqDelegate.getRabbitMqPort());
        if (rabbitMqDelegate.getRabbitMqUser() != null) {
            factory.setUsername(rabbitMqDelegate.getRabbitMqUser());
        }
        if (rabbitMqDelegate.getRabbitMqPass() != null) {
            factory.setPassword(rabbitMqDelegate.getRabbitMqPass());
        } else if (rabbitMqDelegate.getRabbitMqPassFile() != null) {
            try {
                factory.setPassword(Files.readAllLines(Paths.get(rabbitMqDelegate.getRabbitMqPassFile())).get(0));
            } catch (IOException e) {
                LOGGER.error("Could not read rabbitMq password file: ", e);
            }
        }
        if (rabbitMqDelegate.isRabbitMqTLS()) {
            try {
                factory.useSslProtocol();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                LOGGER.error("Could not setup rabbitMq TLS: ", e);
            }
        }
        try {
            this.connection = factory.newConnection();
            this.channel = connection.createChannel();
            this.channel.queueDeclare(SCAN_JOB_QUEUE, false, false, false, null);
            this.channel.queueDeclare(DONE_NOTIFY_QUEUE, false, false, false, null);
        } catch (IOException | TimeoutException e) {
            LOGGER.error("Could not connect to RabbitMQ: ", e);
            throw new RuntimeException();
        }
    }

    public void submitScanJob(ScanJob scanJob) {
        try {
            this.channel.basicPublish("", SCAN_JOB_QUEUE, null, SerializationUtils.serialize(scanJob));
        } catch (IOException e) {
            LOGGER.error("Failed to submit ScanJob: ", e);
        }
    }

    public void registerScanJobConsumer(ScanJobConsumer scanJobConsumer, int prefetchCount) {
        DeliverCallback deliverCallback =
            (consumerTag, delivery) -> scanJobConsumer.consumeScanJob(SerializationUtils.deserialize(delivery.getBody()), delivery.getEnvelope().getDeliveryTag());
        try {
            channel.basicQos(prefetchCount);
            channel.basicConsume(SCAN_JOB_QUEUE, false, deliverCallback, consumerTag -> {
            });
        } catch (IOException e) {
            LOGGER.error("Failed to register ScanJob consumer: ", e);
        }
    }

    public void sendAck(long deliveryTag) {
        try {
            channel.basicAck(deliveryTag, false);
        } catch (IOException e) {
            LOGGER.error("Failed to send message acknowledgment: ", e);
        }
    }

    public void registerDoneNotificationConsumer(DoneNotificationConsumer doneNotificationConsumer) {
        DeliverCallback deliverCallback =
            (consumerTag, delivery) -> doneNotificationConsumer.consumeDoneNotification(consumerTag, SerializationUtils.deserialize(delivery.getBody()));
        try {
            channel.basicQos(1);
            channel.basicConsume(DONE_NOTIFY_QUEUE, true, deliverCallback, consumerTag -> {
            });
        } catch (IOException e) {
            LOGGER.error("Failed to register DoneNotification consumer: ", e);
        }
    }

    public void notifyOfDoneScanJob(ScanJob scanJob) {
        try {
            this.channel.basicPublish("", DONE_NOTIFY_QUEUE, null, SerializationUtils.serialize(scanJob));
        } catch (IOException e) {
            LOGGER.error("Failed to send notification for done ScanJob: ", e);
        }
    }

    public void closeConnection() {
        try {
            this.channel.close();
            this.connection.close();
        } catch (IOException | TimeoutException e) {
            LOGGER.error("Failed to close RabbitMQ connection: ", e);
        }
    }
}
