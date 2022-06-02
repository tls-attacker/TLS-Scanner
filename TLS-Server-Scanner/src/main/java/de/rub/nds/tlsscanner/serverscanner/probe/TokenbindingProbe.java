/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class TokenbindingProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private List<TokenBindingVersion> supportedTokenBindingVersion;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters;

    public TokenbindingProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.TOKENBINDING, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING, TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS,
            TlsAnalyzedProperty.LIST_SUPPORTED_TOKENBINDINGVERSIONS,
            TlsAnalyzedProperty.LIST_SUPPORTED_TOKENBINDING_KEYPARAMETERS);
    }

    @Override
    public void executeTest() {
        supportedTokenBindingVersion = new LinkedList<>();
        supportedTokenBindingVersion.addAll(getSupportedVersions());
        supportedTokenBindingKeyParameters = new LinkedList<>();
        if (!supportedTokenBindingVersion.isEmpty())
            supportedTokenBindingKeyParameters.addAll(getKeyParameters(supportedTokenBindingVersion.get(0)));
    }

    private List<TokenBindingKeyParameters> getKeyParameters(TokenBindingVersion version) {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddTokenBindingExtension(Boolean.TRUE);
        tlsConfig.setDefaultTokenBindingVersion(version);
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
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddTokenBindingExtension(Boolean.TRUE);
        tlsConfig.setDefaultTokenBindingKeyParameters(TokenBindingKeyParameters.values());
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
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.LIST_SUPPORTED_TOKENBINDINGVERSIONS, supportedTokenBindingVersion);
        put(TlsAnalyzedProperty.LIST_SUPPORTED_TOKENBINDING_KEYPARAMETERS, supportedTokenBindingKeyParameters);
        if (supportedTokenBindingVersion != null && !supportedTokenBindingVersion.isEmpty()) {
            put(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING, TestResults.TRUE);
            List<ExtensionType> list = new LinkedList<>();
            list.add(ExtensionType.TOKEN_BINDING);
            addToList(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS, list);
        } else
            put(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING, TestResults.FALSE);
        addToList(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS, new LinkedList<>());
    }

    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }
}
