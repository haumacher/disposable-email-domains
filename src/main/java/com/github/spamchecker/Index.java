package com.github.spamchecker;

import java.util.Map;
import java.util.Set;

import com.github.spamchecker.model.Classification;

public class Index {
	public Map<String, Classification> addressClassification;
	public Map<String, Set<String>> serviceByMx;
	public Map<String, Set<String>> serviceByAddress;

	public Index(Map<String, Classification> addressClassification, Map<String, Set<String>> serviceByMx,
			Map<String, Set<String>> serviceByAddress) {
		this.addressClassification = addressClassification;
		this.serviceByMx = serviceByMx;
		this.serviceByAddress = serviceByAddress;
	}
}