/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class Tls13Result extends ProbeResult {

    private final List<ProtocolVersion> supportedProtocolVersion;

    private final List<ProtocolVersion> unsupportedProtocolVersion;

    private final List<NamedGroup> supportedNamedGroups;

    private final List<CipherSuite> supportedCipherSuites;

    private final List<ECPointFormat> supportedPointFormats;

    public Tls13Result(List<ProtocolVersion> supportedProtocolVersion,
            List<ProtocolVersion> unsupportedProtocolVersion, List<NamedGroup> supportedNamedGroups,
            List<CipherSuite> supportedCipherSuites, List<ECPointFormat> supportedPointFormats) {
        super(ProbeType.TLS13);
        this.supportedProtocolVersion = supportedProtocolVersion;
        this.unsupportedProtocolVersion = unsupportedProtocolVersion;
        this.supportedNamedGroups = supportedNamedGroups;
        this.supportedCipherSuites = supportedCipherSuites;
        this.supportedPointFormats = supportedPointFormats;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (supportedProtocolVersion != null && unsupportedProtocolVersion != null) {
            for (ProtocolVersion version : supportedProtocolVersion) {
                if (version == ProtocolVersion.TLS13) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT14) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT15) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT16) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT17) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT18) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT19) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT20) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT21) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT22) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT23) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT24) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT25) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT26) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT27) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT28) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28, TestResult.TRUE);
                }
            }
            for (ProtocolVersion version : unsupportedProtocolVersion) {
                if (version == ProtocolVersion.TLS13) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT14) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT15) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT16) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT17) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT18) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT19) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT20) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT21) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT22) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT23) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT24) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT25) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT26) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT27) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13_DRAFT28) {
                    report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28, TestResult.FALSE);
                }

            }
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28, TestResult.COULD_NOT_TEST);
        }
        if (supportedNamedGroups != null) {
            report.setSupportedTls13Groups(supportedNamedGroups);
        }
        if (supportedCipherSuites != null) {
            report.setSupportedTls13CipherSuites(supportedCipherSuites);
        }

        if (report.getVersions() != null) {
            report.getVersions().addAll(supportedProtocolVersion);
        } else {
            report.setVersions(supportedProtocolVersion);
        }

        if (supportedPointFormats != null) {
            TestResult supportsUncompressed = TestResult.FALSE;
            TestResult supportsANSIPrime = TestResult.FALSE;
            TestResult supportsANSIChar2 = TestResult.FALSE;

            for (ECPointFormat format : supportedPointFormats) {
                switch (format) {
                    case UNCOMPRESSED:
                        supportsUncompressed = TestResult.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_PRIME:
                        supportsANSIPrime = TestResult.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_CHAR2:
                        supportsANSIChar2 = TestResult.TRUE;
                }
            }
            report.putResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT_TLS13, supportsUncompressed);
            report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME_TLS13, supportsANSIPrime);
            report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2_TLS13, supportsANSIChar2);
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT_TLS13, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME_TLS13, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2_TLS13, TestResult.COULD_NOT_TEST);
        }

    }
}
