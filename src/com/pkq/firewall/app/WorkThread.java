package com.pkq.firewall.app;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import com.pkq.firewall.agent.FireWallOp;
import com.pkq.firewall.agent.IPTables;

import com.pkq.firewall.common.Constant;
import com.pkq.firewall.message.request.AddRuleRequest;
import com.pkq.firewall.message.request.GetRulesRequest;
import com.pkq.firewall.message.request.DeleteRuleRequest;
import com.pkq.firewall.message.request.GetDefaultRuleRequest;
import com.pkq.firewall.message.response.Response;

import com.alibaba.fastjson.JSON;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pkq.util.OSinfo;

public class WorkThread implements Runnable {
	DatagramPacket dgp;
	DatagramSocket s;
	FireWallOp firewall = null;
	Logger logger = LoggerFactory.getLogger(WorkThread.class);

	public WorkThread(DatagramSocket socket, DatagramPacket packet) {
		this.s = socket;
		this.dgp = packet;
		init();
	}

	void init() {
		if (OSinfo.isWindows()) {
			firewall = new IPTables();
		} else if (OSinfo.isLinux()) {
			firewall = new IPTables();
		} else {
			firewall = null;
		}
	}

	public void run() {
		logger.debug("in workthread run()");
		int len = dgp.getLength();
		logger.debug("in workthread run2()");
		String msgReceived = new String(dgp.getData(), 0, len);
		logger.debug("recv msg:" + msgReceived);

		// 处理接收到的消息
		byte[] sendBuf = null;
		DatagramPacket pSend;
		InetAddress addrClient = dgp.getAddress();
		int portClient = dgp.getPort();
		int lenSend;
		String strSend;
		//处理请求消息，并生成响应消息
		try {
			strSend = doClient(msgReceived);
			//strSend = "hello world";
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			Response response = new Response();
			response.setResultCode(Constant.FALSE_CODE);
			response.setResultMessage(e.getMessage());
			strSend = JSON.toJSONString(response);
		}
		// 发送消息回客户端
		try {
			sendBuf = strSend.getBytes();
			lenSend = sendBuf.length;
			pSend = new DatagramPacket(sendBuf, lenSend, addrClient, portClient);
			s.send(pSend);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	String doClient(String msgReceived) throws Exception {
		if (firewall == null) {
			throw new Exception("unSupport operator system");
		}
		String buffer = null;
		if (msgReceived.contains(Constant.AddRuleToken)) {
			AddRuleRequest request = JSON.parseObject(msgReceived,
					AddRuleRequest.class);
			firewall.addRule(request);
		} else if (msgReceived.contains(Constant.GetRulesToken)) {
			GetRulesRequest request = JSON.parseObject(msgReceived,
					GetRulesRequest.class);
			buffer = firewall.getRules(request);
		}else if (msgReceived.contains(Constant.DelRule)) {
			DeleteRuleRequest request = JSON.parseObject(msgReceived,
					DeleteRuleRequest.class);
			buffer = firewall.deleteRule(request);
		}else if (msgReceived.contains(Constant.GetDefaultRuleRequest)) {
			GetDefaultRuleRequest request = JSON.parseObject(msgReceived,
					GetDefaultRuleRequest.class);
			buffer = firewall.getDefaultRule(request);
		} else {
			String msg = "unkown type request";
			throw new Exception(msg);
		}
		return buffer;
	}
}
