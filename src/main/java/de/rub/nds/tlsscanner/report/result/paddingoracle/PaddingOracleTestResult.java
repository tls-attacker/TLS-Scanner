package de.rub.nds.tlsscanner.report.result.paddingoracle;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.HashMap;
import java.util.List;

public class PaddingOracleTestResult {

    private final Boolean vulnerable;
    private final ProtocolVersion version;
    private final CipherSuite suite;
    private final PaddingVectorGeneratorType vectorGeneratorType;
    private final PaddingRecordGeneratorType recordGeneratorType;
    private final List<VectorResponse> responseMap;
    private final EqualityError equalityError;
    private final boolean shakyScans;
    private final boolean hasScanningError;

    public PaddingOracleTestResult(Boolean vulnerable, ProtocolVersion version, CipherSuite suite, PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType, List<VectorResponse> responseMap, EqualityError equalityError, boolean shakyScans, boolean hasScanningError) {
        this.vulnerable = vulnerable;
        this.version = version;
        this.suite = suite;
        this.vectorGeneratorType = vectorGeneratorType;
        this.recordGeneratorType = recordGeneratorType;
        this.responseMap = responseMap;
        this.equalityError = equalityError;
        this.shakyScans = shakyScans;
        this.hasScanningError = hasScanningError;
    }

    public boolean isShakyScans() {
        return shakyScans;
    }

    public boolean isHasScanningError() {
        return hasScanningError;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public List<VectorResponse> getResponseMap() {
        return responseMap;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    public PaddingVectorGeneratorType getVectorGeneratorType() {
        return vectorGeneratorType;
    }

    public PaddingRecordGeneratorType getRecordGeneratorType() {
        return recordGeneratorType;
    }

    public EqualityError getEqualityError() {
        return equalityError;
    }
}
