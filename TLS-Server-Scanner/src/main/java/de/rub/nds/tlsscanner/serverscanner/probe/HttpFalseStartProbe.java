package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.HttpFalseStartResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class HttpFalseStartProbe extends TlsProbe {

    public HttpFalseStartProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HTTP_FALSE_START, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            return new HttpFalseStartResult(this.privateExecuteTest());
        } catch (Exception exc) {
            LOGGER.error("Could not scan for " + getProbeName(), exc);
            return new HttpFalseStartResult(TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult privateExecuteTest() {
        Config tlsConfig = getConfig();

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = factory
                .createTlsEntryWorkflowtrace(tlsConfig.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(
                new ChangeCipherSpecMessage(),
                new FinishedMessage(),
                this.getHttpsRequest() // immediately send application data
        ));
        trace.addTlsAction(new ReceiveAction(
                new ChangeCipherSpecMessage(),
                new FinishedMessage(),
                new HttpsResponseMessage() // receive application data
        ));

        State state = new State(tlsConfig, trace);
        executeState(state);

        ReceivingAction action = trace.getLastReceivingAction();
        if (action.getReceivedMessages() != null) {
            for (ProtocolMessage message : action.getReceivedMessages()) {
                if (message instanceof HttpsResponseMessage) {
                    // if http response was received the server handled the false start
                    return TestResult.TRUE;
                }
            }
        }
        // received no http response -> maybe server did not understand request
        return TestResult.UNCERTAIN;
    }

    private Config getConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(this.getCipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setHttpsParsingEnabled(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HTTPS);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);

        List<NamedGroup> namedGroups = NamedGroup.getImplemented();
        namedGroups.remove(NamedGroup.ECDH_X25519);
        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        return tlsConfig;
    }

    private HttpsRequestMessage getHttpsRequest() {
        HttpsRequestMessage httpsRequestMessage = new HttpsRequestMessage();
        httpsRequestMessage.setRequestPath("/");

        httpsRequestMessage.getHeader().add(new HostHeader());
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader(
                "Connection",
                "keep-alive"
        ));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
        ));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader(
                "Accept-Encoding",
                "compress, deflate, exi, gzip, br, bzip2, lzma, xz"
        ));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader(
                "Accept-Language",
                "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"
        ));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader(
                "Upgrade-Insecure-Requests",
                "1"
        ));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3449.0 Safari/537.36"
        ));
        return httpsRequestMessage;
    }

    private List<CipherSuite> getCipherSuites() {
        List<CipherSuite> cipherSuites = new LinkedList<>(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        return cipherSuites;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_HTTPS) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new HttpFalseStartResult(TestResult.COULD_NOT_TEST);
    }
}
