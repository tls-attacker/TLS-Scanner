/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import static org.junit.Assume.assumeNotNull;

import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.Image;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerClientManager;
import de.rub.nds.tls.subject.docker.DockerTlsInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractProbeIT {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int MAX_ATTEMPTS = 3;
    private static List<Image> localImages;

    private final TlsImplementationType implementation;
    private final String version;
    private final String additionalParameters;
    private final TransportType transportType;

    private DockerTlsInstance dockerInstance;
    protected ServerReport report;

    public AbstractProbeIT(
            TlsImplementationType implementation, String version, String additionalParameters) {
        this.implementation = implementation;
        this.version = version;
        this.additionalParameters = additionalParameters;
        this.transportType = TransportType.TCP;
    }

    public AbstractProbeIT(
            TlsImplementationType implementation,
            String version,
            String additionalParameters,
            TransportType transportType) {
        this.implementation = implementation;
        this.version = version;
        this.additionalParameters = additionalParameters;
        this.transportType = transportType;
    }

    @BeforeAll
    public void loadList() {
        localImages = DockerTlsManagerFactory.getAllImages();
    }

    @BeforeEach
    public void setUp() throws InterruptedException {
        Security.addProvider(new BouncyCastleProvider());
        DockerClientManager.setDockerServerUsername(System.getenv("DOCKER_USERNAME"));
        DockerClientManager.setDockerServerPassword(System.getenv("DOCKER_PASSWORD"));
        prepareContainer();
    }

    private void prepareContainer() throws DockerException, InterruptedException {
        Image image =
                DockerTlsManagerFactory.getMatchingImage(
                        localImages, implementation, version, ConnectionRole.SERVER);
        getDockerInstance(image);
    }

    private void getDockerInstance(Image image) throws DockerException, InterruptedException {
        DockerTlsManagerFactory.TlsServerInstanceBuilder serverInstanceBuilder;
        if (image != null) {
            serverInstanceBuilder =
                    new DockerTlsManagerFactory.TlsServerInstanceBuilder(image, transportType);
        } else {
            serverInstanceBuilder =
                    new DockerTlsManagerFactory.TlsServerInstanceBuilder(
                                    implementation, version, transportType)
                            .pull();
            localImages = DockerTlsManagerFactory.getAllImages();
            assumeNotNull(
                    image,
                    String.format(
                            "TLS implementation %s %s not available",
                            implementation.name(), version));
        }
        serverInstanceBuilder
                .containerName("server-scanner-test-server-" + UUID.randomUUID())
                .additionalParameters(additionalParameters);
        dockerInstance = serverInstanceBuilder.build();
        dockerInstance.start();
    }

    @AfterEach
    public void tearDown() {
        killContainer();
    }

    private void killContainer() {
        if (dockerInstance != null && dockerInstance.getId() != null) {
            dockerInstance.kill();
        }
    }

    @Test
    public void testProbe() throws InterruptedException {
        LOGGER.info("Testing: " + getTestProbe());
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            try {
                executeScan();
            } catch (Exception ignored) {
                LOGGER.info(
                        "Encountered exception during scanner execution ("
                                + ignored.getMessage()
                                + ")");
            }
            if (!executedAsPlanned()) {
                LOGGER.info("Failed to complete scan, reexecuting...");
                killContainer();
                prepareContainer();
            } else {
                return;
            }
        }
        LOGGER.info("Failed");
    }

    private void executeScan() {
        ServerScannerConfig config = new ServerScannerConfig(new GeneralDelegate());
        config.getClientDelegate()
                .setHost("localhost:" + ((DockerTlsServerInstance) dockerInstance).getPort());
        config.addProbes(getRequiredProbes());
        config.addProbes(getTestProbe());
        TlsServerScanner scanner = new TlsServerScanner(config);
        report = scanner.scan();
    }

    protected abstract boolean executedAsPlanned();

    protected abstract ProbeType getTestProbe();

    protected List<ProbeType> getRequiredProbes() {
        return new LinkedList<>();
    }

    protected boolean verifyProperty(TlsAnalyzedProperty property, TestResult result) {
        return report.getResult(property) == result;
    }
}
