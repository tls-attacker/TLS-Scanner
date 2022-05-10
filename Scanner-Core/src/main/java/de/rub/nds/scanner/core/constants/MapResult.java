/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.constants;

import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public class MapResult<S, T> implements TestResult{

	private String name="MapResult";
	private final Map<S, T> map;
	
	public MapResult(Map<S, T> map){
		this.map = map;
	}
	
	public MapResult(Map<S, T> map, String name){
		this.map = map;
		this.name = name;
	}
	
	public Map<S, T> getMap() {
		return this.map;
	}
	
	@Override
	public String name() {
		return this.name;
	}
}
