/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after.prime;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class CommonDhLoader {

    private CommonDhLoader() {
    }

    public static List<CommonDhValues> loadCommonDhValues() {
        try {
            List<CommonDhValues> commonValuesList = new LinkedList<>();
            JSONParser parser = new JSONParser();
            InputStream resourceAsStream =
                CommonDhLoader.class.getClassLoader().getResourceAsStream("common/common.json");
            Object obj = parser.parse(new InputStreamReader(resourceAsStream));

            JSONObject jsonObject = (JSONObject) obj;
            JSONArray companyList = (JSONArray) jsonObject.get("data");

            Iterator<JSONObject> iterator = companyList.iterator();
            while (iterator.hasNext()) {
                JSONObject commonDh = iterator.next();
                BigInteger generator = new BigInteger((String) commonDh.get("g").toString());
                Long length = (Long) commonDh.get("length");
                String name = (String) commonDh.get("name");
                BigInteger modulus = new BigInteger((String) commonDh.get("p"));
                Boolean prime = (Boolean) commonDh.get("prime");
                Boolean safePrime = (Boolean) commonDh.get("safe_prime");
                commonValuesList.add(new CommonDhValues(generator, modulus, length.intValue(), prime, safePrime, name));
            }
            return commonValuesList;
        } catch (IOException | ParseException ex) {
            throw new RuntimeException("Could not load CommonDh Values");
        }
    }

}
