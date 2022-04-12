/*
 * Copyright 2022 nk.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

public class ClientRecordFragmentationResult extends ProbeResult<ClientReport> {
    private Boolean supported = null;

    public ClientRecordFragmentationResult(Boolean supported) {
        super(TlsProbeType.RECORD_FRAGMENTATION);

        this.supported = supported;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supported);
    }

    public Boolean getSupported() {
        return supported;
    }

    public void setSupported(Boolean supported) {
        this.supported = supported;
    }
}
