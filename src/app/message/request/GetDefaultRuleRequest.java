package app.message.request;

import app.Constant;

public class GetDefaultRuleRequest {
	String msgType = Constant.GetDefaultRuleRequest; //消息类型
	String host;
	String ruleType;
	String direction;
	
	public String getHost() {
		return host;
	}
	public void setHost(String host) {
		this.host = host;
	}
	public String getRuleType() {
		return ruleType;
	}
	public void setRuleType(String ruleType) {
		this.ruleType = ruleType;
	}
	public String getDirection() {
		return direction;
	}
	public void setDirection(String direction) {
		this.direction = direction;
	}

}
