package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ExtensionResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.TokenbindingResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author robert
 */
public class TokenbindingProbe extends TlsProbe {

    public TokenbindingProbe(ScannerConfig config) {
        super(ProbeType.TOKENBINDING, config, 0);
    }

    @Override
    public ProbeResult executeTest() {
        List<TokenBindingVersion> supportedTokenBindingVersion = new LinkedList<>();
        supportedTokenBindingVersion.addAll(getSupportedVersions());
        List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = new LinkedList<>();
        if (supportedTokenBindingVersion.size() != 0) {
            supportedTokenBindingKeyParameters.addAll(getKeyParameters(supportedTokenBindingVersion.get(0)));
        }
        return new TokenbindingResult(supportedTokenBindingVersion, supportedTokenBindingKeyParameters);
    }

    private List<TokenBindingKeyParameters> getKeyParameters(TokenBindingVersion version) {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopRecievingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        // Dont send extensions if we are in sslv2
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddExtendedMasterSecretExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddTokenBindingExtension(Boolean.TRUE);
        tlsConfig.setDefaultTokenBindingVersion(version);
        List<NamedGroup> nameGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(nameGroups);
        List<TokenBindingKeyParameters> supportedParameters = new LinkedList<>();
        List<TokenBindingKeyParameters> toTestList = new ArrayList<>(Arrays.asList(TokenBindingKeyParameters.values()));

        while (!toTestList.isEmpty()) {
            tlsConfig.setDefaultTokenBindingKeyParameters(toTestList);
            State state = new State(tlsConfig);
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,
                    state);

            try {
                workflowExecutor.executeWorkflow();
                if (state.getTlsContext().isExtensionNegotiated(ExtensionType.TOKEN_BINDING)) {
                    supportedParameters.addAll(state.getTlsContext().getTokenBindingKeyParameters());
                    for (TokenBindingKeyParameters param : state.getTlsContext().getTokenBindingKeyParameters()) {
                        toTestList.remove(param);
                    }
                }
            } catch (WorkflowExecutionException ex) {
                LOGGER.warn("Could not execute Workflow to determine supported Tokenbinding Key Parameters");
                LOGGER.debug(ex);
            }
        }
        return supportedParameters;
    }

    private Set<TokenBindingVersion> getSupportedVersions() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopRecievingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        // Dont send extensions if we are in sslv2
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddExtendedMasterSecretExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddTokenBindingExtension(Boolean.TRUE);
        tlsConfig.setDefaultTokenBindingKeyParameters(TokenBindingKeyParameters.values());
        List<NamedGroup> nameGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(nameGroups);
        Set<TokenBindingVersion> supportedVersions = new HashSet<>();
        for (TokenBindingVersion version : TokenBindingVersion.values()) {
            try {
                tlsConfig.setDefaultTokenBindingVersion(version);
                State state = new State(tlsConfig);
                WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,
                        state);
                workflowExecutor.executeWorkflow();
                if (state.getTlsContext().isExtensionNegotiated(ExtensionType.TOKEN_BINDING)) {
                    supportedVersions.add(state.getTlsContext().getTokenBindingVersion());
                }

            } catch (WorkflowExecutionException ex) {
                LOGGER.warn("Could not execute Workflow to determine supported Tokenbinding Versions");
                LOGGER.debug(ex);
            }
        }
        return supportedVersions;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new TokenbindingResult(null, null);
    }
}
