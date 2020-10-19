/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.report.result;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.util.MapUtil;
import de.rub.nds.tlsscanner.clientscanner.util.helper.UpdatableXmlSeeAlso;

@XmlSeeAlso({})
// this is automated via UpdatableXmlSeeAlso
@XmlAccessorType(XmlAccessType.FIELD)
public class ParametrizedClientProbeResult<K, V> extends ClientProbeResult {
    private static Set<Class<?>> seeAlso = UpdatableXmlSeeAlso.patch(ParametrizedClientProbeResult.class);

    private final transient Class<? extends IProbe> clazz;
    @SuppressWarnings("squid:S1948")
    // sonarlint complains that K,V aren't serializable, but when they are, JAXB
    // complains that serializable is an interface... So rather make the linter
    // unhappy than our serialization lib
    private final Map<K, V> resultMap;

    public ParametrizedClientProbeResult(Class<? extends IProbe> clazz, K resultKey, V resultValue) {
        this.clazz = clazz;
        resultMap = new HashMap<>();
        resultMap.put(resultKey, resultValue);
        seeAlso.add(resultKey.getClass());
        seeAlso.add(resultValue.getClass());
    }

    public V get(K key) {
        return resultMap.get(key);
    }

    @Override
    @SuppressWarnings({ "squid:S2445", "unchecked", "rawtypes", "squid:S3740" })
    // sonarlint: Blocks should be synchronized on "private final" fields
    // also suppress any unchecked and raw types warnings...
    public void merge(ClientReport report) {
        synchronized (report) {
            if (report.hasResult(clazz)) {
                ParametrizedClientProbeResult other = report.getResult(clazz, ParametrizedClientProbeResult.class);
                MapUtil.mergeIntoFirst(other.resultMap, resultMap);
                report.markAsChangedAndNotify();
            } else {
                report.putResult(clazz, this);
            }
        }

    }

}
