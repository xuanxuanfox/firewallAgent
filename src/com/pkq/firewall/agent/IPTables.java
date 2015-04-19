package com.pkq.firewall.agent;

import java.util.ArrayList;
import java.util.List;

import org.apache.oro.text.regex.MatchResult;
import org.apache.oro.text.regex.Pattern;
import org.apache.oro.text.regex.PatternCompiler;
import org.apache.oro.text.regex.PatternMatcherInput;
import org.apache.oro.text.regex.Perl5Compiler;
import org.apache.oro.text.regex.Perl5Matcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pkq.util.SystemUtil;
import com.pkq.firewall.common.Constant;
import com.pkq.firewall.model.ProtPorts;
import com.pkq.firewall.model.Rule;

import com.pkq.firewall.message.request.AddRuleRequest;
import com.pkq.firewall.message.request.DeleteRuleRequest;
import com.pkq.firewall.message.request.GetDefaultRuleRequest;
import com.pkq.firewall.message.response.GetDefaultRuleResponse;
import com.pkq.firewall.message.response.GetRulesResponse;
import com.pkq.firewall.message.response.Response;
import com.pkq.firewall.message.request.GetRulesRequest;


public class IPTables extends FireWallOp {
	static final String Action_allow_iptables = "ACCEPT";
	static final String Action_deny_iptables = "DROP";
	static final String Direction_in = "INPUT";
	static final String Direction_out = "OUTPUT";
	static final String Multiport_token = "multiport";
	static final String SourcePort_token = "spt:";
	static final String DestPort_token = "dpt:";
	static final String State_token = " state";
	Logger logger = LoggerFactory.getLogger(IPTables.class);

	/**
	 * 按照获取默认策略对象生成iptable命令
	 */
	String buildGetDefaultRuleCommand(GetDefaultRuleRequest request) {
		String strRet = null;
		convertRequestGetDefaultRuleRequestToHost(request); // 转换为Iptables的request
		strRet = String.format("iptables -nL %s --line-number", request
				.getDirection());
		logger.debug("buildGetDefaultRuleCommand:" + strRet);
		return strRet;
	}

	String buildDelRuleCommand(DeleteRuleRequest request) throws Exception{
		String token = "-";
		String strRet = null;
		String ruleId = request.getId();
		logger.debug("buildDelRuleCommand, ruleId="+ruleId);
		//id组合规则：ip-direction-line,要分解出行号，根据行号删除
		int pos = ruleId.indexOf(token);
		logger.debug("buildDelRuleCommand, pos="+pos);
		if(pos<1){
			throw new Exception("rule id 格式不对");
		}
		String lineNumber = ruleId.substring(pos+token.length());
		logger.debug("buildDelRuleCommand, lineNumber="+lineNumber);
		String directionInId = ruleId.substring(0,pos);
		logger.debug("buildDelRuleCommand, directionInId="+directionInId);
		strRet = String.format("iptables -D %s %s", directionInId,lineNumber);
		logger.debug("buildDelRuleCommand:" + strRet);
		return strRet;
	}
	
	String buildAddRuleCommand(AddRuleRequest request) {
		Rule rule = request.getRule();
		String strRet = null;
		String remoteIp = "";
		String remotePort = "";

		// 如果策略中含ip
		if (rule.getRemoteIp() != null
				&& rule.getRemoteIp().trim().length() > 0) {
			remoteIp = " -d " + rule.getRemoteIp().trim();
		}
		// 如果是多个端口
		if (rule.getRemotePort() != null && rule.getRemotePort().contains(",")) {
			remotePort = " -m multiport --dport " + rule.getRemotePort().trim();
		} else {
			remotePort = " --dport " + rule.getRemotePort().trim();
		}

		convertRequestRuleToHost(rule); // 转为iptables的rule
		strRet = String.format("iptables -A %s -p %s %s%s -m state --state NEW,ESTABLISHED -j %s", rule
				.getDirection(), rule.getProtocol(), remoteIp, remotePort, rule
				.getAction());
		logger.debug("buildAddRuleCommand:" + strRet);
		return strRet;
	}

	String buildGetRulesCommand(GetRulesRequest request) {
		String strRet = null;

		convertGetRulesRequestToHost(request);
		strRet = String.format("iptables -nL %s --line-number", request
				.getDirection());
		logger.debug("buildGetRulesCommand:" + strRet);
		return strRet;
	}

	/***
	 * 解析同意response，正常情况下返回的是空，如果返回不空，表示出现错误
	 */
	Response parseCommonResponse(String strRsp) throws Exception {
		Response response = new Response();
		if (null == strRsp) {
			return response;
		}
		strRsp = strRsp.trim();
		if (0 == strRsp.length()) {
			return response;
		} else {
			response.setResultCode(Constant.FALSE_CODE);
			response.setResultMessage(strRsp);
			return response;
		}
	}

	/***
	 * 解析获取策略消息
	 */
	public GetRulesResponse parseGetRulesResponse(String direction, int start, int limit, String message) throws Exception {

		int nLine = 1;
		int pos = 0;

		String strLineToken = "\r\n";
		int lenLineToken = strLineToken.length();
		String strARule = "";
		String strDefaultPolicy = "";
		String strtemp = message;
		int nNow=0;

		logger.debug("in parseGetRulesResponse, message:" + strtemp);
		// 第一行是默认策略，例子： Chain INPUT (policy DROP)
		pos = strtemp.indexOf(strLineToken);
		logger.debug("pos1:" + pos);
		if (pos > 0) {
			strDefaultPolicy = strtemp.substring(0, pos);
		} else {
			throw new Exception("get faultRule failure, message:" + message);
		}
		logger.debug("strDefaultPolicy:{" + strDefaultPolicy+"}");
		String policy = parseDefaultPolicy(direction,strDefaultPolicy);
		logger.debug("policy:{" + policy+"}");
		
		// 第二行是数据栏标题，不是数据，跳过，例子： target prot opt source destination
		strtemp = strtemp.substring(pos + lenLineToken);
		pos = strtemp.indexOf(strLineToken);
		strtemp = strtemp.substring(pos + lenLineToken);
		logger.debug("rule data :\n" + strtemp );
		// -----------
		//从第三行开始，
		// 每行代表一条策略，依次取出行策略
		pos = strtemp.indexOf(strLineToken);
		Rule rule;
		List<Rule> rules = new ArrayList<Rule>();
		while (pos > 0) {
			strARule = strtemp.substring(0, pos).trim();
			logger.debug("strARule: "+ strARule);
			nNow++;
			if(nNow<start){ //如果没有到起始行，继续
				continue;
			}
			if(nNow>start + limit){ //如果超过了最大行，结束
				break; 
			}
			if(strARule.length()<1){
				continue;
			}
			rule = parseRule(direction, strARule);
			if(null!=rule){
				rules.add(rule);
			}
			strtemp = strtemp.substring(pos + lenLineToken);
			pos = strtemp.indexOf(strLineToken);
		}
		//
		GetRulesResponse response = new GetRulesResponse();
		response.setDefaultPolicy(policy);
		response.setRules(rules);

		return response;
	}

	/***************************************************************************
	 * 解析获取防火墙规则消息中的一条规则，规则数据格式样例如下：
	 * 
	 * @param message
	 * @return 防火墙规则对象
	 * @throws Exception
	 */
	public Rule parseRule(String direction, String message) throws Exception {
		if (direction.equals(IPTables.Direction_in)) {
			return parseInputRule(direction,message);
		} else {
			//return parseOutputRule(message);
			return parseInputRule(direction,message);
		}
	}

	/***************************************************************************
	 * 解析获取防火墙规则消息中的一条input规则，规则数据格式样例如下： 1 ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0
	 * tcp dpt:22 state NEW,ESTABLISHED
	 * 
	 * @param message
	 * @return
	 * @throws Exception
	 */
	public Rule parseInputRule(String direction, String message) throws Exception {
		Rule rule = new Rule();
		String strReg1 = "^(\\d)+\\s+(\\w+)\\s+(\\w+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(.+)\\s+state\\s+(\\S+)";
		String strReg2 = "^(\\d)+\\s+(\\w+)\\s+(\\w+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(.+)";
		String strReg;
		
		boolean isMultiport = message.contains(IPTables.Multiport_token);;
		boolean hasState = message.contains(IPTables.State_token);
		boolean hasDestPort = message.contains(IPTables.DestPort_token);
		
		if( !isMultiport && !hasDestPort){ //如果即不包含Multiport标记，也不包含dpt:标记，则表示是特殊的规则，如icmp，忽略
			return null;
		}
		
		if(hasState){  //如果包含state标记
			strReg = strReg1;
		}else{
			strReg = strReg2;
		}
		String target;
		String prot;
		String prot_ports;
		String opt;
		String source;
		String destination;
		String remotePort;
		String state;
		String nLine;
		ProtPorts pps;

		PatternCompiler pc = new Perl5Compiler();
		Pattern pa;

		pa = pc.compile(strReg);
		MatchResult result = null;

		Perl5Matcher ma = new Perl5Matcher();
		PatternMatcherInput mi = new PatternMatcherInput(message);
		if (ma.contains(mi, pa)) {
			result = ma.getMatch();
			int nsize = result.groups();
			nLine = result.group(1).trim();
			target = result.group(2).trim();
			target = convertHostActionToThis(target); // 转换为本协议用的action
			prot = result.group(3).trim();
			opt = result.group(4).trim();
			source = result.group(5).trim();
			destination = result.group(6).trim();
			prot_ports = result.group(7).trim();
			pps = parseProt_ports(prot_ports);
			if(message.contains(IPTables.State_token)){
				state = result.group(8).trim();
			}
			//id组合规则：ip-direction-line
			String ruleID = String.format("%s-%s", direction,nLine);
			rule.setId(ruleID);
			rule.setAction(target);
			rule.setProtocol(prot);
			rule.setPort(pps.getPorts());
			// remotePort = parseRemotePort(destination);
			rule.setRemotePort(pps.getRemotePorts());
			rule.setRemoteIp(destination);
		} else {
			throw new Exception("parseInputRule failure, message:" + message);
		}
		return rule;
	}


	/**
	 * 
	 * @param message，数据格式有3种，分别代表单个端口,单个端口含源端口，和多个端口，
	 *            例子： tcp dpt:8080 或 multiport dports 3306,3307
	 * @return 远程端口,可能会多个
	 */
	public ProtPorts parseProt_ports(String message) throws Exception {
		ProtPorts pps = new ProtPorts();
		String strReg1 = "(.+) dpt:(.+)";
		String strReg2 = "multiport (.+) (.+)";
		String strReg3 = ".+ spt:(.+) dpt:(.+)";
		String strReg;
		String strDestPort = "";
		String strSrcPort = "";

		if (message.contains(IPTables.Multiport_token)) {
			strReg = strReg2;
		} else if (message.contains(IPTables.SourcePort_token)) {
			strReg = strReg3;
		}else{
			strReg = strReg1;
		}
		PatternCompiler pc = new Perl5Compiler();
		Pattern pa;

		pa = pc.compile(strReg);
		MatchResult result = null;

		Perl5Matcher ma = new Perl5Matcher();
		PatternMatcherInput mi = new PatternMatcherInput(message);
		if (ma.contains(mi, pa)) {
			result = ma.getMatch();
			strDestPort = result.group(2).trim();
			if (message.contains(IPTables.SourcePort_token)) {
				strSrcPort = result.group(1).trim();
			}
		} else {
			throw new Exception("parse remote port failure, message:" + message);
		}
		pps.setPorts(strSrcPort);
		pps.setRemotePorts(strDestPort);
		return pps;
	}

	/***************************************************************************
	 * 解析获取默认策略消息
	 * 
	 * @param message
	 *            策略消息字符串
	 * @return 默认策略对象
	 */
	GetDefaultRuleResponse parseDefaultRuleResponse(String direction,String message)
			throws Exception {
		GetDefaultRuleResponse response = new GetDefaultRuleResponse();
		int start=1;
		int limit=1;
		/* 默认策略是从获取策略的第一行中获取
		 * */
		GetRulesResponse gr = parseGetRulesResponse(direction, start, limit, message);
		response.setDirection(direction);
		response.setPolicy(gr.getDefaultPolicy());
		return response;
	}
	
	 String parseDefaultPolicy(String direction, String message) throws Exception{
			ProtPorts pps = new ProtPorts();
			String strReg = "Chain \\w+ \\(policy (\\w+)\\)";
			String policy = "";

			PatternCompiler pc = new Perl5Compiler();
			Pattern pa;

			pa = pc.compile(strReg);
			MatchResult result = null;

			Perl5Matcher ma = new Perl5Matcher();
			PatternMatcherInput mi = new PatternMatcherInput(message);
			if (ma.contains(mi, pa)) {
				result = ma.getMatch();
				policy = result.group(1).trim();
				policy = convertHostActionToThis(policy);
			} else {
				throw new Exception("parse parseDefaultPolicy failure, message:" + message);
			}
			return policy;		
	}

	/***************************************************************************
	 * 把消息中的action和direction转为主机(iptables)的action和direction
	 * 
	 * @param rule
	 */
	void convertRequestRuleToHost(Rule rule) {

		String action = rule.getAction().equals(Constant.Action_allow) ? Action_allow_iptables
				: Action_deny_iptables;
		rule.setAction(action);

		String direction = rule.getDirection().equals(Constant.Direction_in) ? IPTables.Direction_in
				: IPTables.Direction_out;
		rule.setDirection(direction);
	}

	/***************************************************************************
	 * 把消息中的action和direction转为iptables的action和direction
	 * 
	 * @param request
	 */
	void convertRequestGetDefaultRuleRequestToHost(GetDefaultRuleRequest request) {
		String direction = request.getDirection().equals(Constant.Direction_in) ? IPTables.Direction_in
				: IPTables.Direction_out;
		request.setDirection(direction);
	}

	void convertGetRulesRequestToHost(GetRulesRequest request) {
		String direction = request.getDirection().equals(Constant.Direction_in) ? IPTables.Direction_in
				: IPTables.Direction_out;
		request.setDirection(direction);
	}

	String convertHostActionToThis(String hostAction) {
		String action = hostAction.equals(IPTables.Action_allow_iptables) ? Constant.Action_allow
				: Constant.Action_deny;
		return action;
	}
	
	String convertHostDirectionToThis(String hostDirection){
		String direction = hostDirection.equals(IPTables.Direction_in) ? Constant.Direction_in
				: Constant.Direction_out;
		return direction;
	}
	
	String convertThisDirectionToHost(String thisDirection) {
		String direction = thisDirection.equals(Constant.Direction_in) ? IPTables.Direction_in
				: IPTables.Direction_out;
		return direction;
	}

}
