/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.client.adapter;

import java.util.List;
import java.util.function.UnaryOperator;

import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.HostConfig;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerExecInstance;
import de.rub.nds.tls.subject.docker.DockerTlsClientInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.exceptions.TlsVersionNotFoundException;
import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.report.result.BasicClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult.EContentShown;

public class DockerLibAdapter implements ClientAdapter {
    private static final Logger LOGGER = LogManager.getLogger();
    private final TlsImplementationType type;
    private final String version;
    private DockerTlsClientInstance client;
    private final UnaryOperator<HostConfig> hostConfigHook;

    public DockerLibAdapter(TlsImplementationType type, String version, UnaryOperator<HostConfig> hostConfigHook) {
        this.type = type;
        this.version = version;
        this.hostConfigHook = hostConfigHook;
    }

    public DockerLibAdapter(TlsImplementationType type, String version) {
        this(type, version, null);
    }

    @Override
    public void prepare() {
        try {
            client = DockerTlsManagerFactory.getTlsClientBuilder(type, version).autoRemove(true).connectOnStartup(false)
                .insecureConnection(false).hostConfigHook(hostConfigHook).build();
        } catch (DockerException e) {
            LOGGER.error("Failed to create client", e);
            if (client != null) {
                client.close();
            }
            throw new RuntimeException(e);
        } catch (TlsVersionNotFoundException e) {
            LOGGER.error("Could not find Version {} for Type {}", version, type);
            if (LOGGER.isInfoEnabled()) {
                List<String> versions = DockerTlsManagerFactory.getAvailableVersions(ConnectionRole.CLIENT, type);
                LOGGER.info("Available Versions for {}", type);
                for (String v : versions) {
                    LOGGER.info(v);
                }
            } else {
                LOGGER.error("Info logger is disabled - not printing available versions");
            }
            throw e;
        } catch (InterruptedException e) {
            LOGGER.error("Failed to create client (interrupt)", e);
            if (client != null) {
                client.close();
            }
            Thread.currentThread().interrupt();
        }
        // client should not be able to be null;
        // An exception should already have been thrown
        client.start();
    }

    @Override
    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException {
        try {
            DockerExecInstance ei = (DockerExecInstance) client.connect(hostname, port);
            ei.frameHandler.awaitStarted();
            ei.frameHandler.awaitCompletion();
            long exitCode = ei.getExitCode();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Exit code {}", exitCode);
                for (String ln : ei.frameHandler.getLines()) {
                    LOGGER.debug(ln);
                }
            }
            // TODO distinguish further details
            // As of now we only check the exit code to determine whether the content was shown or not
            // Some clients may behave differently, which would need to be handled here
            return new BasicClientAdapterResult(exitCode == 0 ? EContentShown.SHOWN : EContentShown.ERROR);
        } catch (DockerException e) {
            throw new RuntimeException("Failed to have client connect to target", e);
        }
    }

    @Override
    public void cleanup() {
        if (client != null) {
            client.close();
            client = null;
        }
    }

    @Override
    public ClientInfo getReportInformation() {
        return new DockerClientInfo(type, version);
    }

    public static class DockerClientInfo extends ClientInfo {
        public final TlsImplementationType type;
        public final String version;

        public DockerClientInfo(TlsImplementationType type, String version) {
            this.type = type;
            this.version = version;
        }

        @Override
        public String toShortString() {
            return String.format("%s [%s]", type, version);
        }

    }

}