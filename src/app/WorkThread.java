package app;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import app.firewall.FireWallOp;
import app.firewall.IPTables;
import app.message.request.AddRuleRequest;
import app.message.request.GetRulesRequest;
import app.message.response.Response;

import com.alibaba.fastjson.JSON;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pkq.util.OSinfo;

public class WorkThread implements Runnable {
	DatagramPacket dgp;
	DatagramSocket s;
	FireWallOp firewall = null;
	Logger logger = LoggerFactory.getLogger(WorkThread.class);

	public WorkThread(DatagramSocket socket, DatagramPacket packet) {
		this.s = socket;
		this.dgp = packet;
	}

	void init() {
		if (OSinfo.isWindows()) {

		} else if (OSinfo.isLinux()) {
			firewall = new IPTables();
		} else {
			firewall = null;
		}

	}

	public void run() {
		int len = 0;
		len = dgp.getLength();
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
		} else {
			String msg = "unkown type request";
			throw new Exception(msg);
		}

		return buffer;
	}
}
