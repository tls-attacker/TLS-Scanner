/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.test;

import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.Image;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerClientManager;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import de.rub.nds.tls.subject.docker.build.DockerBuilder;
import java.security.Security;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assume;
import org.junit.jupiter.api.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractDockerbasedIT {
    private static List<Image> localImages;

    private final TlsImplementationType implementation;
    private final String version;
    private final String additionalParameters;
    private final TransportType transportType;

    private DockerTlsServerInstance dockerInstance;

    public AbstractDockerbasedIT(
            TlsImplementationType implementation,
            String version,
            String additionalParameters,
            TransportType transportType) {
        this.implementation = implementation;
        this.version = version;
        this.additionalParameters = additionalParameters;
        this.transportType = transportType;
    }

    public AbstractDockerbasedIT(
            TlsImplementationType implementation, String version, String additionalParameters) {
        this(implementation, version, additionalParameters, TransportType.TCP);
    }

    @BeforeAll
    public void loadList() {
        try {
            DockerClientManager.getDockerClient().listContainersCmd().exec();
        } catch (Exception ex) {
            Assume.assumeNoException(ex);
        }
        localImages = DockerTlsManagerFactory.getAllImages();
    }

    @BeforeEach
    public void setUp() throws InterruptedException {
        Security.addProvider(new BouncyCastleProvider());
        DockerClientManager.setDockerServerUsername(System.getenv("DOCKER_USERNAME"));
        DockerClientManager.setDockerServerPassword(System.getenv("DOCKER_PASSWORD"));
        prepareContainer();
    }

    protected void prepareContainer() throws DockerException, InterruptedException {
        Image image =
                DockerTlsManagerFactory.getMatchingImage(
                        localImages,
                        implementation,
                        version,
                        DockerBuilder.NO_ADDITIONAL_BUILDFLAGS,
                        ConnectionRole.SERVER);
        Assertions.assertNotNull(
                image,
                String.format(
                        "TLS implementation %s %s not available", implementation.name(), version));
        createDockerInstance(image);
    }

    private void createDockerInstance(Image image) throws DockerException, InterruptedException {
        DockerTlsManagerFactory.TlsServerInstanceBuilder serverInstanceBuilder =
                new DockerTlsManagerFactory.TlsServerInstanceBuilder(image, transportType);
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

    protected void killContainer() {
        if (dockerInstance != null && dockerInstance.getId() != null) {
            dockerInstance.kill();
        }
    }

    protected String getServerAddress() {
        return "localhost:" + dockerInstance.getPort();
    }
}
