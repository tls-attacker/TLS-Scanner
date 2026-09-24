/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.passive;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

/**
 * Tests that EcPublicKeyExtractor only extracts EC points from TLS 1.3 key shares and skips key
 * shares of groups without elliptic curve parameters (pure and hybrid ML-KEM / Kyber groups).
 */
public class EcPublicKeyExtractorTest {

    private WorkflowTrace testTrace;
    private EcPublicKeyExtractor extractor;

    @BeforeEach
    public void setUp() {
        testTrace = new WorkflowTrace();
        extractor = new EcPublicKeyExtractor();
    }

    public static Stream<NamedGroup> provideNonEcGroups() {
        return Arrays.stream(NamedGroup.values())
                .filter(group -> group.isMlKemGroup() || group.isKyber());
    }

    private static KeyShareEntry createKeyShareEntry(NamedGroup group, byte[] publicKey) {
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setGroup(group.getValue());
        keyShareEntry.setPublicKey(publicKey);
        return keyShareEntry;
    }

    private ReceiveAction generateServerHello(KeyShareEntry... keyShareEntries) {
        KeyShareExtensionMessage keyShareExtension = new KeyShareExtensionMessage();
        keyShareExtension.setRetryRequestMode(false);
        keyShareExtension.setKeyShareList(List.of(keyShareEntries));
        ServerHelloMessage serverHello = new ServerHelloMessage();
        serverHello.addExtension(keyShareExtension);

        ReceiveAction receiveAction = Mockito.mock(ReceiveAction.class);
        Mockito.when(receiveAction.getReceivedMessages()).thenReturn(List.of(serverHello));
        return receiveAction;
    }

    private State createClientState() {
        Config config = new Config();
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        return new State(config, testTrace);
    }

    @ParameterizedTest
    @MethodSource("provideNonEcGroups")
    public void testNonEcKeyShareIsSkipped(NamedGroup group) {
        // the payload length is irrelevant as the key share must not be parsed at all
        testTrace.addTlsAction(generateServerHello(createKeyShareEntry(group, new byte[1216])));
        State state = createClientState();

        assertDoesNotThrow(() -> extractor.extract(state));
        assertEquals(0, extractor.getContainer().getNumberOfExtractedValues());
    }

    @Test
    public void testUnknownGroupKeyShareIsSkipped() {
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setGroup(new byte[] {(byte) 0xFA, (byte) 0xFA});
        keyShareEntry.setPublicKey(new byte[32]);
        testTrace.addTlsAction(generateServerHello(keyShareEntry));
        State state = createClientState();

        assertDoesNotThrow(() -> extractor.extract(state));
        assertEquals(0, extractor.getContainer().getNumberOfExtractedValues());
    }

    @Test
    public void testEcKeyShareIsExtractedAlongsideNonEcKeyShare() {
        NamedEllipticCurveParameters curveParameters = NamedEllipticCurveParameters.SECP256R1;
        Point basePoint = curveParameters.getGroup().getBasePoint();
        byte[] encodedPoint =
                PointFormatter.formatToByteArray(
                        curveParameters, basePoint, PointFormat.UNCOMPRESSED);

        testTrace.addTlsAction(
                generateServerHello(
                        createKeyShareEntry(NamedGroup.X25519_MLKEM768, new byte[1120]),
                        createKeyShareEntry(NamedGroup.SECP256R1, encodedPoint)));
        State state = createClientState();

        extractor.extract(state);

        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(basePoint, extractor.getContainer().getExtractedValueList().get(0));
    }
}
