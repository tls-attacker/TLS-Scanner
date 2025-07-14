/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ByteArraySerializer;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.passive.TrackableValue;
import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.IntegerResult;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.LongResult;
import de.rub.nds.scanner.core.probe.result.MapResult;
import de.rub.nds.scanner.core.probe.result.ObjectResult;
import de.rub.nds.scanner.core.probe.result.SetResult;
import de.rub.nds.scanner.core.probe.result.StringResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.converter.AnalyzedPropertyKeyDeserializer;
import de.rub.nds.tlsscanner.core.converter.ByteArrayDeserializer;
import de.rub.nds.tlsscanner.core.converter.TrackableValueTypeKeyDeserializer;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlsscanner.core.util.VersionInformation;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.serverscanner.leak.BleichenbacherOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackProbabilities;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerReport extends TlsScanReport {
    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Returns Jackson modules for serialization configuration.
     *
     * @return array of Jackson modules for JSON serialization
     */
    public static Module[] getSerializerModules() {
        return new Module[] {
            new SimpleModule()
                    .addSerializer(new ByteArraySerializer())
                    .addDeserializer(byte[].class, new ByteArrayDeserializer())
                    .addKeyDeserializer(
                            AnalyzedProperty.class, new AnalyzedPropertyKeyDeserializer())
                    .addKeyDeserializer(
                            TrackableValue.class, new TrackableValueTypeKeyDeserializer()),
            new JodaModule()
        };
    }

    private final String sniHostname;
    private final String host;
    private final Integer port;

    // Version information for JSON output
    private String tlsScannerVersion = VersionInformation.getTlsScannerVersion();
    private String tlsAttackerVersion = VersionInformation.getTlsAttackerVersion();
    private String javaVersion = VersionInformation.getJavaVersion();

    private Boolean serverIsAlive = null;
    private Boolean speaksProtocol = null;
    private Boolean isHandshaking = null;

    // Config profile used to limit our Client Hello
    private String configProfileIdentifier;
    private String configProfileIdentifierTls13;

    /** Constructs an empty ServerReport. */
    public ServerReport() {
        this(null, null, null);
    }

    /**
     * Constructs a ServerReport for the specified host and port.
     *
     * @param host the hostname or IP address of the server
     * @param port the port number of the server
     */
    public ServerReport(String host, Integer port) {
        this(null, host, port);
    }

    /**
     * Constructs a ServerReport with SNI hostname, host and port.
     *
     * @param sniHostname the SNI hostname to use in the TLS handshake
     * @param host the hostname or IP address of the server
     * @param port the port number of the server
     */
    public ServerReport(String sniHostname, String host, Integer port) {
        super();
        this.sniHostname = sniHostname;
        this.host = host;
        this.port = port;
    }

    @Override
    public synchronized void serializeToJson(OutputStream outputStream) {
        try {
            ServerReportJsonMapper mapper = new ServerReportJsonMapper();
            mapper.objectMapper.writeValue(outputStream, this);
        } catch (IOException e) {
            LOGGER.error("Error serializing ServerReport to JSON", e);
        }
    }

    @Override
    public synchronized String getRemoteName() {
        if (sniHostname != null) {
            return sniHostname + "(" + host + "):" + port;
        } else {
            return host + ":" + port;
        }
    }

    public synchronized String getHost() {
        return host;
    }

    public synchronized Integer getPort() {
        return port;
    }

    /**
     * Returns the version of TLS-Scanner used for this scan.
     *
     * @return the TLS-Scanner version string
     */
    public synchronized String getTlsScannerVersion() {
        return tlsScannerVersion;
    }

    /**
     * Returns the version of TLS-Attacker used for this scan.
     *
     * @return the TLS-Attacker version string
     */
    public synchronized String getTlsAttackerVersion() {
        return tlsAttackerVersion;
    }

    /**
     * Returns the Java version used for this scan.
     *
     * @return the Java version string
     */
    public synchronized String getJavaVersion() {
        return javaVersion;
    }

    /**
     * Returns whether the server was reachable during the scan.
     *
     * @return true if the server was reachable, false otherwise
     */
    public synchronized Boolean getServerIsAlive() {
        return serverIsAlive;
    }

    /**
     * Sets whether the server was reachable during the scan.
     *
     * @param serverIsAlive true if the server was reachable, false otherwise
     */
    public synchronized void setServerIsAlive(Boolean serverIsAlive) {
        this.serverIsAlive = serverIsAlive;
    }

    public synchronized CheckPattern getMacCheckPatternAppData() {
        ObjectResult<CheckPattern> objectResult =
                getObjectResult(TlsAnalyzedProperty.MAC_CHECK_PATTERN_APP_DATA, CheckPattern.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized CheckPattern getVerifyCheckPattern() {
        ObjectResult<CheckPattern> objectResult =
                getObjectResult(TlsAnalyzedProperty.VERIFY_CHECK_PATTERN, CheckPattern.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    /**
     * Returns whether the server speaks the expected protocol.
     *
     * @return true if the server speaks the protocol, false otherwise
     */
    public synchronized Boolean getSpeaksProtocol() {
        return speaksProtocol;
    }

    /**
     * Sets whether the server speaks the expected protocol.
     *
     * @param speaksProtocol true if the server speaks the protocol, false otherwise
     */
    public synchronized void setSpeaksProtocol(Boolean speaksProtocol) {
        this.speaksProtocol = speaksProtocol;
    }

    public synchronized Boolean getIsHandshaking() {
        return isHandshaking;
    }

    public synchronized void setIsHandshaking(Boolean isHandshaking) {
        this.isHandshaking = isHandshaking;
    }

    public synchronized Integer getCookieLength() {
        IntegerResult integerResult = getIntegerResult(TlsAnalyzedProperty.COOKIE_LENGTH);
        return integerResult == null ? null : integerResult.getValue();
    }

    public synchronized GcmPattern getGcmPattern() {
        ObjectResult<GcmPattern> objectResult =
                getObjectResult(TlsAnalyzedProperty.GCM_PATTERN, GcmPattern.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized Integer getHandshakeSuccessfulCounter() {
        IntegerResult integerResult =
                getIntegerResult(TlsAnalyzedProperty.HANDSHAKE_SUCCESFUL_COUNTER);
        return integerResult == null ? null : integerResult.getValue();
    }

    public synchronized Integer getHandshakeFailedCounter() {
        IntegerResult integerResult =
                getIntegerResult(TlsAnalyzedProperty.HANDSHAKE_FAILED_COUNTER);
        return integerResult == null ? null : integerResult.getValue();
    }

    public synchronized Integer getConnectionInsecureCounter() {
        IntegerResult integerResult =
                getIntegerResult(TlsAnalyzedProperty.CONNECTION_INSECURE_COUNTER);
        return integerResult == null ? null : integerResult.getValue();
    }

    @Override
    public synchronized String toString() {
        return new ServerReportPrinter(
                        this,
                        ScannerDetail.NORMAL,
                        DefaultPrintingScheme.getDefaultPrintingScheme(),
                        false)
                .getFullReport();
    }

    public synchronized CheckPattern getMacCheckPatternFinished() {
        ObjectResult<CheckPattern> objectResult =
                getObjectResult(TlsAnalyzedProperty.MAC_CHECK_PATTERN_FIN, CheckPattern.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized Long getHstsMaxAge() {
        LongResult longResult = getLongResult(TlsAnalyzedProperty.HSTS_MAX_AGE);
        return longResult == null ? null : longResult.getValue();
    }

    public synchronized Integer getHpkpMaxAge() {
        IntegerResult integerResult = getIntegerResult(TlsAnalyzedProperty.HPKP_MAX_AGE);
        return integerResult == null ? null : integerResult.getValue();
    }

    public synchronized Integer getWeakestDhStrength() {
        IntegerResult integerResult = getIntegerResult(TlsAnalyzedProperty.WEAKEST_DH_STRENGTH);
        return integerResult == null ? null : integerResult.getValue();
    }

    public synchronized List<InvalidCurveResponse> getInvalidCurveTestResultList() {
        ListResult<InvalidCurveResponse> listResult =
                getListResult(
                        TlsAnalyzedProperty.INVALID_CURVE_TEST_RESULT, InvalidCurveResponse.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<RaccoonAttackProbabilities> getRaccoonAttackProbabilities() {
        if (getResult(TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES)
                == TestResults.NOT_TESTED_YET) {
            return null;
        }
        ListResult<RaccoonAttackProbabilities> listResult =
                getListResult(
                        TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES,
                        RaccoonAttackProbabilities.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<InformationLeakTest<DirectRaccoonOracleTestInfo>>
            getRaccoonTestResultList() {
        @SuppressWarnings("unchecked")
        ListResult<InformationLeakTest<DirectRaccoonOracleTestInfo>> listResult =
                (ListResult<InformationLeakTest<DirectRaccoonOracleTestInfo>>)
                        getListResult(TlsAnalyzedProperty.DIRECT_RACCOON_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<InformationLeakTest<BleichenbacherOracleTestInfo>>
            getBleichenbacherTestResultList() {
        @SuppressWarnings("unchecked")
        ListResult<InformationLeakTest<BleichenbacherOracleTestInfo>> listResult =
                (ListResult<InformationLeakTest<BleichenbacherOracleTestInfo>>)
                        getListResult(TlsAnalyzedProperty.BLEICHENBACHER_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HpkpPin> getNormalHpkpPins() {
        ListResult<HpkpPin> listResult =
                getListResult(TlsAnalyzedProperty.NORMAL_HPKP_PINS, HpkpPin.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HpkpPin> getReportOnlyHpkpPins() {
        ListResult<HpkpPin> listResult =
                getListResult(TlsAnalyzedProperty.REPORT_ONLY_HPKP_PINS, HpkpPin.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SimulatedClientResult> getSimulatedClientsResultList() {
        ListResult<SimulatedClientResult> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS, SimulatedClientResult.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ApplicationProtocol> getSupportedApplicationProtocols() {
        ListResult<ApplicationProtocol> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_APPLICATIONS, ApplicationProtocol.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<CommonDhValues> getCommonDhValues() {
        SetResult<CommonDhValues> setResult =
                getSetResult(TlsAnalyzedProperty.COMMON_DH_VALUES, CommonDhValues.class);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnesses() {
        MapResult<NamedGroup, NamedGroupWitness> mapResult =
                getMapResult(
                        TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES,
                        NamedGroup.class,
                        NamedGroupWitness.class);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnessesTls13() {
        MapResult<NamedGroup, NamedGroupWitness> mapResult =
                getMapResult(
                        TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13,
                        NamedGroup.class,
                        NamedGroupWitness.class);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized String getConfigProfileIdentifier() {
        return configProfileIdentifier;
    }

    public synchronized void setConfigProfileIdentifier(String configProfileIdentifier) {
        this.configProfileIdentifier = configProfileIdentifier;
    }

    public synchronized String getConfigProfileIdentifierTls13() {
        return configProfileIdentifierTls13;
    }

    public synchronized void setConfigProfileIdentifierTls13(String configProfileIdentifierTls13) {
        this.configProfileIdentifierTls13 = configProfileIdentifierTls13;
    }

    public synchronized List<byte[]> getSupportedQuicVersions() {
        ListResult<byte[]> listResult = getListResult(QuicAnalyzedProperty.VERSIONS, byte[].class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized QuicTransportParameters getQuicTransportParameters() {
        ObjectResult<QuicTransportParameters> objectResult =
                getObjectResult(
                        QuicAnalyzedProperty.TRANSPORT_PARAMETERS, QuicTransportParameters.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized ConnectionCloseFrame getQuicTls12HandshakeConnectionCloseFrame() {
        ObjectResult<ConnectionCloseFrame> objectResult =
                getObjectResult(
                        QuicAnalyzedProperty.TLS12_HANDSHAKE_CONNECTION_CLOSE_FRAME,
                        ConnectionCloseFrame.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized String getIpv6Address() {
        StringResult stringResult = getStringResult(QuicAnalyzedProperty.IPV6_ADDRESS);
        return stringResult == null ? null : stringResult.getValue();
    }
}
