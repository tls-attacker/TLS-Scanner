package de.rub.nds.tlsscanner.clientscanner.client.adapter;

import com.spotify.docker.client.exceptions.DockerException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerExecInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.instance.TlsClientInstance;
import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;

public class DockerLibAdapter implements IClientAdapter {
    private static final Logger LOGGER = LogManager.getLogger();
    private final TlsImplementationType type;
    private final String version;
    private TlsClientInstance client;

    public DockerLibAdapter(TlsImplementationType type, String version) {
        this.type = type;
        this.version = version;
    }

    @Override
    public void prepare(boolean clean) {
        try {
            client = DockerTlsManagerFactory
                    .getTlsClientBuilder(type, version)
                    .autoRemove(true)
                    .connectOnStartup(false)
                    .insecureConnection(false)
                    .build();
        } catch (DockerException e) {
            LOGGER.error("Failed to create client", e);
            if (client != null) {
                client.close();
            }
        } catch (InterruptedException e) {
            LOGGER.error("Failed to create client (interrupt)", e);
            if (client != null) {
                client.close();
            }
            Thread.currentThread().interrupt();
        }
        if (client == null) {
            // usually null should not be possible; An exception should have been thrown
            throw new NullPointerException("Could not get client");
        }
        try {
            client.start();
        } catch (DockerException e) {
            LOGGER.error("Failed to start client", e);
            client.close();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to start client (interrupt)", e);
            client.close();
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException {
        try {
            DockerExecInstance ei = (DockerExecInstance) client.connect(hostname, port);
            while (ei.isRunning()) {
                Thread.sleep(50);
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(ei.logStream.readFully());
            }
            return null;
        } catch (DockerException e) {
            throw new RuntimeException("Failed to have client connect to target", e);
        }
    }

    @Override
    public void cleanup(boolean deleteAll) {
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