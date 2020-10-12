package de.rub.nds.tlsscanner.clientscanner.probe;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeRsaParametersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe.SupportedCipherSuitesResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

// see https://www.smacktls.com/smack.pdf section V-D
public class FreakProbe extends BaseProbe {
    private static final int P_LEN = 256;
    private static final int Q_LEN = 256;
    private static final int N_LEN = P_LEN + Q_LEN;
    protected static final List<CipherSuite> RSA_SUITES;
    static {
        RSA_SUITES = CipherSuite.getImplemented();
        RSA_SUITES.removeIf(suite -> !suite.name().startsWith("TLS_RSA_"));
    }

    private Random rnd = new Random();

    public FreakProbe(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return ProbeRequirements.TRUE()
                .needResultOfTypeMatching(
                        SupportedCipherSuitesProbe.class,
                        SupportedCipherSuitesResult.class,
                        SupportedCipherSuitesResult::supportsKeyExchangeRSA,
                        "Client does not support RSA key exchange");
    }

    @SuppressWarnings("squid:S3776") // sonarlint says this function is too complex...
    private void patchTrace(WorkflowTrace trace, ServerKeyExchangeMessage ske, TlsAction fixKeysAction) throws DispatchException {
        // patch send action (which sends SH, CERT, SHD) to include SKE after CERT
        boolean done = false;
        for (TlsAction a : trace.getTlsActions()) {
            if (a instanceof SendAction) {
                boolean foundSH = false;
                List<ProtocolMessage> msgs = ((SendAction) a).getMessages();
                for (ProtocolMessage msg : msgs) {
                    if (!foundSH) {
                        if (msg instanceof ServerHelloMessage) {
                            foundSH = true;
                        }
                    } else {
                        if (msg instanceof CertificateMessage) {
                            // append SKE
                            msgs.add(msgs.indexOf(msg) + 1, ske);
                            done = true;
                            break;
                        }
                    }
                }
                if (done) {
                    // add fixKeysAction
                    trace.addTlsAction(trace.getTlsActions().indexOf(a) + 1, fixKeysAction);
                    break;
                }
            }
        }
        if (!done) {
            throw new DispatchException("Did not find CH, CERT");
        }
    }

    @Override
    public FreakResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        Config config = state.getConfig();
        WorkflowTrace trace = state.getWorkflowTrace();
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setSupportedVersions(ProtocolVersion.SSL2, ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12);
        config.setDefaultSelectedCipherSuite(RSA_SUITES.get(0));
        config.setDefaultServerSupportedCiphersuites(RSA_SUITES);
        extendWorkflowTraceToApplication(trace, config);

        BigInteger p, q, N, e, d, phi;
        e = BigInteger.valueOf(65537);
        do {
            p = BigInteger.probablePrime(P_LEN, rnd);
            q = BigInteger.probablePrime(Q_LEN, rnd);
            N = p.multiply(q);
            assert N.bitLength() <= N_LEN;
            phi = p.subtract(BigInteger.ONE);
            BigInteger q1 = q.subtract(BigInteger.ONE);
            phi = phi.multiply(q1);
        } while (!e.gcd(phi).equals(BigInteger.ONE));
        d = e.modInverse(N);
        assert d.multiply(e).mod(phi).equals(BigInteger.ONE);
        config.setDefaultServerRSAModulus(N);
        config.setDefaultServerRSAPublicKey(e);
        config.setDefaultServerRSAPrivateKey(d);
        RSAServerKeyExchangeMessage ske = new RSAServerKeyExchangeMessage();
        // set mod, pubKey so they are not null
        ske.setModulus(N.toByteArray());
        ske.setPublicKey(e.toByteArray());
        // then use ModifiableVariable to set the export pubKey
        ske.getModulus().setModification(new ByteArrayExplicitValueModification(N.toByteArray()));
        ske.getPublicKey().setModification(new ByteArrayExplicitValueModification(e.toByteArray()));

        // for SKE we need the cert keys to do the signing
        // after that we need the export keys to do the decryption

        // TODO I did not get decryption to work, even though it should
        // This might be the client 's fault.
        // Nonetheless, we can detect if a client misbehaves and sends a small CKE.
        TlsAction fixKeysAction = new ChangeRsaParametersAction(N, e, d);
        patchTrace(trace, ske, fixKeysAction);
        executeState(state, dispatchInformation);
        return new FreakResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class FreakResult extends ClientProbeResult {
        public final boolean vulnerable;

        public FreakResult(State state) {
            // we say the client is vulnerable if the sent a small CKE
            boolean found = false;
            boolean vuln = false;
            for (TlsAction a : state.getWorkflowTrace().getTlsActions()) {
                if (a instanceof ReceiveAction) {
                    for (ProtocolMessage msg : ((ReceiveAction) a).getMessages()) {
                        if (msg instanceof ClientKeyExchangeMessage) {
                            ClientKeyExchangeMessage cke = (ClientKeyExchangeMessage) msg;
                            BigInteger c = new BigInteger(1, cke.getPublicKey().getValue());
                            vuln = c.bitLength() <= N_LEN;
                            found = true;
                            break;
                        }
                    }
                    if (found) {
                        break;
                    }
                }
            }
            vulnerable = vuln;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(FreakProbe.class, this);
        }

    }

}