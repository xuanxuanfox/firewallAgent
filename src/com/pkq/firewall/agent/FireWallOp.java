package com.pkq.firewall.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSON;

import com.pkq.util.SystemUtil;
import com.pkq.firewall.model.Rule;
import com.pkq.firewall.message.request.AddRuleRequest;
import com.pkq.firewall.message.request.DeleteRuleRequest;
import com.pkq.firewall.message.request.GetDefaultRuleRequest;
import com.pkq.firewall.message.response.GetDefaultRuleResponse;
import com.pkq.firewall.message.response.GetRulesResponse;
import com.pkq.firewall.message.response.Response;
import com.pkq.firewall.message.request.GetRulesRequest;

public abstract class FireWallOp {
	Logger logger = LoggerFactory.getLogger(IPTables.class);
	
	abstract String buildAddRuleCommand(AddRuleRequest request);
	abstract String buildGetRulesCommand(GetRulesRequest request) ;
	abstract String buildGetDefaultRuleCommand(GetDefaultRuleRequest request) ;
	abstract String buildDelRuleCommand(DeleteRuleRequest request) throws Exception;
	abstract Response parseCommonResponse(String strRsp) throws Exception;
	abstract GetDefaultRuleResponse parseDefaultRuleResponse(String direction, String strRsp) throws Exception;
	abstract GetRulesResponse parseGetRulesResponse(String direction, int start, int limit, String message) throws Exception;
	
	public String addRule(AddRuleRequest request) throws Exception{
		String strCmd = buildAddRuleCommand(request);
		String strRsp = SystemUtil.runCommand(strCmd);
		String logMsg = String.format("run command:%s \n return: %s", strCmd,strRsp);
		logger.debug( logMsg );
		Response response = parseCommonResponse(strRsp);
		String jsonStringSend = JSON.toJSONString(response);
		return jsonStringSend;
	}
	
	public String getRules(GetRulesRequest request) throws Exception{
		String logMsg;
		String strCmd = buildGetRulesCommand(request);
		logMsg = String.format("run command:%s \n ", strCmd);
		String strRsp = SystemUtil.runCommand(strCmd);
		logMsg = String.format("run command:%s \n return: %s", strCmd,strRsp);
		logger.debug( logMsg );
		GetRulesResponse response = parseGetRulesResponse(request.getDirection(),request.getStartRow(),request.getLimit(),strRsp);
		String jsonStringSend = JSON.toJSONString(response);
		//logger.debug( "send back:\n" + jsonStringSend );
		return jsonStringSend;
	}

	
	public String getDefaultRule(GetDefaultRuleRequest request) throws Exception{
		String strCmd = buildGetDefaultRuleCommand(request);
		String strRsp = SystemUtil.runCommand(strCmd);
		//String strRsp = "Chain INPUT (policy ACCEPT)";
		String logMsg = String.format("run command:%s \n return: %s", strCmd,strRsp);
		logger.debug( logMsg );
		GetDefaultRuleResponse response = parseDefaultRuleResponse(request.getDirection(),strRsp);
		String jsonStringSend = JSON.toJSONString(response);
		return jsonStringSend;
	}
	
	public String deleteRule(DeleteRuleRequest request) throws Exception{
		
		String strCmd = buildDelRuleCommand(request);
		String strRsp = SystemUtil.runCommand(strCmd);
		//String strRsp = "Chain INPUT (policy ACCEPT)";
		String logMsg = String.format("run command:%s \n return: %s", strCmd,strRsp);
		logger.debug( logMsg );
		Response response = parseCommonResponse(strRsp);
		String jsonStringSend = JSON.toJSONString(response);
		return jsonStringSend;
		
	}
}
