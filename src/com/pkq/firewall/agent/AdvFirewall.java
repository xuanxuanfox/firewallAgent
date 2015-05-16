package com.pkq.firewall.agent;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import com.pkq.firewall.common.Constant;
import com.pkq.firewall.message.request.AddRuleRequest;
import com.pkq.firewall.message.request.DeleteRuleRequest;
import com.pkq.firewall.message.request.GetDefaultRuleRequest;
import com.pkq.firewall.message.request.GetRulesRequest;
import com.pkq.firewall.message.response.GetDefaultRuleResponse;
import com.pkq.firewall.message.response.GetRulesResponse;
import com.pkq.firewall.message.response.Response;
import com.pkq.firewall.model.Rule;
import com.pkq.util.StringUtils;

public class AdvFirewall extends FireWallOp {
	static final String Action_allow_advfirewall = "allow";
	static final String Action_deny_advfirewall = "block";
	static final String Direction_in_advfirewall = "in";
	static final String Direction_out_advfirewall = "out";
	static final String Direction_in_policy_advfirewall = "inbound";
	static final String Direction_out_policy_advfirewall = "outbound";

	@Override
	String buildAddRuleCommand(AddRuleRequest request) {
		Rule rule = request.getRule();
		String strRet = null;
		String remoteIp = "";
		String remotePort = "";

		// 如果策略中含ip
		if (rule.getRemoteIp() != null
				&& rule.getRemoteIp().trim().length() > 0) {
			remoteIp = " remoteip=" + rule.getRemoteIp().trim();
		}
		remotePort = " localport=" + rule.getRemotePort().trim();
		convertRequestRuleToHost(rule); // 转为AdvFirewall的rule
		strRet = String
				.format(
						"netsh advfirewall firewall add rule name=pkqrule dir=%s action=%s protocol=%s localport=%s %s",
						rule.getDirection(), rule.getAction(), rule
								.getProtocol(), remotePort, remoteIp);
		logger.debug("buildAddRuleCommand:" + strRet);
		return strRet;
	}

	@Override
	String buildDelRuleCommand(DeleteRuleRequest request) throws Exception {
		String strRet = null;

		strRet = String
				.format(
						"netsh advfirewall firewall delete rule name=pkqrule protocol= %s localport=%s",
						request.getProtocol(), request.getPort());
		logger.debug("buildDelRuleCommand:" + strRet);
		return strRet;
	}

	@Override
	String buildGetDefaultRuleCommand(GetDefaultRuleRequest request) {
		String strRet = null;

		strRet = String
				.format("netsh advfirewall  show allprofiles firewallpolicy");
		logger.debug("buildGetDefaultRuleCommand:" + strRet);
		return strRet;
	}

	@Override
	String buildGetRulesCommand(GetRulesRequest request) {
		String strRet = null;

		convertGetRulesRequestToHost(request);
		strRet = String.format(
				"netsh advfirewall firewall show rule name=pkqrule dir=%s",
				request.getDirection());
		logger.debug("buildGetRulesCommand:" + strRet);
		return strRet;
	}

	@Override
	Response parseCommonResponse(String strRsp) throws Exception {
		Response response = new Response();

		strRsp = StringUtils.replaceBlank(strRsp); // 去掉首尾空格和换行符
		String token = AdvFirewallToken.getToken(strRsp,
				AdvFirewallToken.TOKEN_TYPE_OK);
		// 没有找到特征字符串,则表示失败
		if (token == null) {
			response.setResultCode(Constant.FALSE_CODE);
			response.setResultMessage(strRsp);
		}
		return response;
	}

	@Override
	/*
	 * 数据格式样例： 防火墙策略 BlockInbound,AllowOutbound
	 * 
	 * 公用配置文件 设置:
	 * ---------------------------------------------------------------------
	 * 防火墙策略 BlockInbound,AllowOutbound 确定。
	 */
	GetDefaultRuleResponse parseDefaultRuleResponse(String direction,
			String message) throws Exception {
		GetDefaultRuleResponse response = new GetDefaultRuleResponse();
		String token = AdvFirewallToken.getToken(message,
				AdvFirewallToken.TOKEN_TYPE_DEFAULTPOLICY);
		String strPolicy;
		String[] policys;
		String aPolicy, aPolicyValue;
		int i = 0;
		HashMap mapPolicy = new HashMap();
		int pos, posNewLine;
		pos = message.indexOf(token);
		posNewLine = message.indexOf(AdvFirewallToken.tokenNewLine, pos);
		strPolicy = message.substring(pos + token.length(), posNewLine); // 值类似为：
																			// BlockInbound,AllowOutbound
		strPolicy = strPolicy.toLowerCase(); // 全转为小写，便于处理，变成
												// blockinbound,allowoutbound
		policys = strPolicy.split(",");
		// 解析strPolicy，并存如hashmap中，便于后面取值
		for (i = 0; i < policys.length; i++) {
			aPolicy = policys[i]; // blockinbound 或者 allowoutbound
			aPolicy = StringUtils.replaceBlank(aPolicy);
			aPolicyValue = aPolicy.substring(0, 5); // 去前5个字符，block或者allow
			aPolicyValue = convertHostActionToThis(aPolicyValue);
			if (aPolicy.indexOf(Direction_in_policy_advfirewall) > 0) {
				mapPolicy.put(Constant.Direction_in, aPolicyValue);
			} else if (aPolicy.indexOf(Direction_out_policy_advfirewall) > 0) {
				mapPolicy.put(Constant.Direction_out, aPolicyValue);
			}
		}
		// 根据传入的direction参数值，从hashmap中取得其值
		aPolicyValue = (String) mapPolicy.get(direction);
		response.setDirection(direction);
		response.setPolicy(aPolicyValue);
		return response;
	}

	@Override
	GetRulesResponse parseGetRulesResponse(String direction, int start,
			int limit, String message) throws Exception {
		int nLine = 1;
		int i, total = 0;
		//int nNow = 0;
		Rule rule;
		List<Rule> rules = new ArrayList<Rule>();
		GetRulesResponse response = new GetRulesResponse();
		String StrValue;
		String strRemoteIp;
		String remoteIp,protocol,localPort,remotePort,action;
		String tokenRemoteIp,tokenProtocol,tokenLocalPort,tokenRemotePort,tokenAction;
		int posRemoteIp, posNewLine,posProtocol,posLocalPort,posRemotePort,posAction;
		
		//----- get all token
		tokenRemoteIp = AdvFirewallToken.getToken(message,
				AdvFirewallToken.TOKEN_TYPE_GETRULE_REMOTEIP);
		tokenProtocol = AdvFirewallToken.getToken(message,
				AdvFirewallToken.TOKEN_TYPE_GETRULE_PROTOCOL);
		tokenLocalPort = AdvFirewallToken.getToken(message,
				AdvFirewallToken.TOKEN_TYPE_GETRULE_LOCALPORT);
		tokenRemotePort = AdvFirewallToken.getToken(message,
				AdvFirewallToken.TOKEN_TYPE_GETRULE_REMOTEPORT);
		tokenAction = AdvFirewallToken.getToken(message,
				AdvFirewallToken.TOKEN_TYPE_GETRULE_ACTION);
		//-----
		posRemoteIp = message.indexOf(tokenRemoteIp);
		while (posRemoteIp > 0) {
			// --- Remote Ip
			posNewLine = message.indexOf(AdvFirewallToken.tokenNewLine,
					posRemoteIp);
			strRemoteIp = message.substring(posRemoteIp
					+ tokenRemoteIp.length(), posNewLine); // 值类似为：远程 IP: 任何
			//StrValue = strRemoteIp.substring(tokenRemoteIp.length());
			remoteIp = StringUtils.replaceBlank(strRemoteIp);
			nLine++;
			if (nLine <= start) { // 如果没有到起始行，继续获取下一个
				total++; //总数量加1
				posRemoteIp = message.indexOf(tokenRemoteIp, posNewLine);
				continue;
			}
			rule = new Rule();
			rule.setDirection(direction);
			remoteIp = convertHostRuleValueToThis(remoteIp);
			rule.setRemoteIp(remoteIp);
			//---- protocol
			posProtocol = message.indexOf(tokenProtocol, posRemoteIp);
			posNewLine = message.indexOf(AdvFirewallToken.tokenNewLine,
					posProtocol);
			protocol= message.substring(posProtocol+tokenProtocol.length(),posNewLine);
			protocol = StringUtils.replaceBlank(protocol);
			rule.setProtocol(protocol);
			//----localPort
			posLocalPort = message.indexOf(tokenLocalPort, posRemoteIp);
			posNewLine = message.indexOf(AdvFirewallToken.tokenNewLine,
					posLocalPort);
			localPort= message.substring(posLocalPort+tokenLocalPort.length(),posNewLine);
			localPort = StringUtils.replaceBlank(localPort);
			localPort = convertHostRuleValueToThis(localPort);
			rule.setPort(localPort);
			//----remotePort
			posRemotePort = message.indexOf(tokenRemotePort, posRemoteIp);
			posNewLine = message.indexOf(AdvFirewallToken.tokenNewLine,
					posRemotePort);
			remotePort= message.substring(posRemotePort+tokenRemotePort.length(),posNewLine);			
			remotePort = StringUtils.replaceBlank(remotePort);
			//会出现去不了的空格
			remotePort = convertHostRuleValueToThis(remotePort);
			rule.setRemotePort(remotePort);
			//----action
			posAction = message.indexOf(tokenAction, posRemoteIp);
			posNewLine = message.indexOf(AdvFirewallToken.tokenNewLine,
					posAction);
			action= message.substring(posAction+tokenAction.length(),posNewLine);
			action = StringUtils.replaceBlank(action);
			action = convertHostRuleValueToThis(action);
			rule.setAction(action);
			//-----
			total++; //总数量加1
			if (nLine > start + limit) { // 如果超过了最大行，不加入数据了，只计算总数量

			} else {
				rules.add(rule);
			}
			// 获取下一个
			posRemoteIp = message.indexOf(tokenRemoteIp, posNewLine);
		}
		// response.setDefaultPolicy(policy);
		response.setRules(rules);
		response.setTotal(total);

		return response;
	}

	@Override
	void runSaveCommand() {
		// do nothing

	}

	/***************************************************************************
	 * 把消息中的action和direction转为主机(iptables)的action和direction
	 * 
	 * @param rule
	 */
	void convertRequestRuleToHost(Rule rule) {

		String action = rule.getAction().equals(Constant.Action_allow) ? AdvFirewall.Action_allow_advfirewall
				: AdvFirewall.Action_deny_advfirewall;
		rule.setAction(action);

		String direction = rule.getDirection().equals(Constant.Direction_in) ? AdvFirewall.Direction_in_advfirewall
				: AdvFirewall.Direction_out_advfirewall;
		rule.setDirection(direction);
	}

	void convertGetRulesRequestToHost(GetRulesRequest request) {
		String direction = request.getDirection().equals(Constant.Direction_in) ? AdvFirewall.Direction_in_advfirewall
				: AdvFirewall.Direction_out_advfirewall;
		request.setDirection(direction);
	}

	String convertHostActionToThis(String hostAction) {
		// "BlockInbound,AllowOutbound"
		String action = hostAction.equals(AdvFirewall.Action_allow_advfirewall) ? Constant.Action_allow
				: Constant.Action_deny;
		return action;
	}
	
	String convertHostRuleValueToThis(String in){
		String ret;
		if(in.indexOf("任何")>=0){
			ret = Constant.ANY;
		}else if(in.equals("允许")){
			ret = Constant.Action_allow;
		}else if(in.equals("阻止")){
			ret = Constant.Action_deny;
		}else{
			ret = in;
		}
		return ret;
	}
	
}
