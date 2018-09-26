package de.rub.nds.tlsscanner.report.result.paddingoracle;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
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
    private final HashMap<Integer, List<ResponseFingerprint>> responseMap;
    private final EqualityError equalityError;

    public PaddingOracleTestResult(Boolean vulnerable, ProtocolVersion version, CipherSuite suite, PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType, HashMap<Integer, List<ResponseFingerprint>> responseMap, EqualityError equalityError) {
        this.vulnerable = vulnerable;
        this.version = version;
        this.suite = suite;
        this.vectorGeneratorType = vectorGeneratorType;
        this.recordGeneratorType = recordGeneratorType;
        this.responseMap = responseMap;
        this.equalityError = equalityError;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public HashMap<Integer, List<ResponseFingerprint>> getResponseMap() {
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
