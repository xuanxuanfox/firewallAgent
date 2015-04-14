package app.message.response;

import java.util.List;

import app.Rule;

public class GetRulesResponse extends Response{
	String defaultPolicy;
	
	List<Rule> rules;

	public List<Rule> getRules() {
		return rules;
	}

	public void setRules(List<Rule> rules) {
		this.rules = rules;
	}

	public String getDefaultPolicy() {
		return defaultPolicy;
	}

	public void setDefaultPolicy(String defaultPolicy) {
		this.defaultPolicy = defaultPolicy;
	}
}
