/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.TokenbindingResult;
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

    public TokenbindingProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.TOKENBINDING, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<TokenBindingVersion> supportedTokenBindingVersion = new LinkedList<>();
            supportedTokenBindingVersion.addAll(getSupportedVersions());
            List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = new LinkedList<>();
            if (!supportedTokenBindingVersion.isEmpty()) {
                supportedTokenBindingKeyParameters.addAll(getKeyParameters(supportedTokenBindingVersion.get(0)));
            }
            return new TokenbindingResult(supportedTokenBindingVersion, supportedTokenBindingKeyParameters);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new TokenbindingResult(null, null);
        }
    }

    private List<TokenBindingKeyParameters> getKeyParameters(TokenBindingVersion version) {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        // Don't send extensions if we are in SSLv2
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
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
            executeState(state);
            if (state.getTlsContext().isExtensionNegotiated(ExtensionType.TOKEN_BINDING)) {
                supportedParameters.addAll(state.getTlsContext().getTokenBindingKeyParameters());
                for (TokenBindingKeyParameters param : state.getTlsContext().getTokenBindingKeyParameters()) {
                    toTestList.remove(param);
                }
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
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        // Don't send extensions if we are in SSLv2
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
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
                executeState(state);
                if (state.getTlsContext().isExtensionNegotiated(ExtensionType.TOKEN_BINDING)) {
                    supportedVersions.add(state.getTlsContext().getTokenBindingVersion());
                }

            } catch (WorkflowExecutionException ex) {
                LOGGER.error("Could not execute Workflow to determine supported Tokenbinding Versions", ex);
            }
        }
        return supportedVersions;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new TokenbindingResult(null, null);
    }
}
