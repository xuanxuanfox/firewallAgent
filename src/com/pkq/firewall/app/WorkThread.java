package com.pkq.firewall.app;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;

import com.pkq.firewall.agent.FireWallOp;
import com.pkq.firewall.agent.IPTables;

import com.pkq.firewall.common.Constant;
import com.pkq.firewall.message.request.AddRuleRequest;
import com.pkq.firewall.message.request.GetRulesRequest;
import com.pkq.firewall.message.request.DeleteRuleRequest;
import com.pkq.firewall.message.request.GetDefaultRuleRequest;
import com.pkq.firewall.message.request.UpdateRequest;
import com.pkq.firewall.message.response.Response;

import com.alibaba.fastjson.JSON;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pkq.util.OSinfo;

public class WorkThread extends Thread {
	// --
	DatagramPacket dgp;
	DatagramSocket s;
	// --
	Socket connection;
	// --
	FireWallOp firewall = null;
	Logger logger = LoggerFactory.getLogger(WorkThread.class);

	public WorkThread(DatagramSocket socket, DatagramPacket packet) {
		this.s = socket;
		this.dgp = packet;
		firewall = AgentApp.firewall;
	}

	public WorkThread(Socket connection) {
		this.connection = connection;
		firewall = AgentApp.firewall;
	}

	public void run() {
		// doUDP();
		doTCP();
	}

	private void doTCP() {
		String strSend;
		try {
			InputStream in = connection.getInputStream();
			byte[] buffer = new byte[256];
			int nread = in.read(buffer, 0, 256);
			String strRecv = new String(buffer, 0, nread);
			logger.debug("recv msg:" + strRecv);
			// 处理接收到的消息
			byte[] sendBuf = null;
			DatagramPacket pSend;
			int lenSend;
			strSend = doClient(strRecv);
			logger.debug("strSend:\n" + strSend);
			
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			Response response = new Response();
			response.setResultCode(Constant.FALSE_CODE);
			response.setResultMessage(e.getMessage());
			strSend = JSON.toJSONString(response);
		}
		// 发送消息回客户端
		sendBack_TCP(strSend);
	}
	
	private void sendBack_TCP(String strSend) {
		try{
		OutputStreamWriter out = new
		 OutputStreamWriter(connection.getOutputStream( ));
		 out.write(strSend);
		 out.flush();
		}
		 catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
	}

	private void doUDP() {
		int len = dgp.getLength();
		String msgReceived = new String(dgp.getData(), 0, len);
		logger.debug("recv msg:" + msgReceived);

		// 处理接收到的消息
		byte[] sendBuf = null;
		DatagramPacket pSend;
		int lenSend;
		String strSend;
		// 处理请求消息，并生成响应消息
		try {
			strSend = doClient(msgReceived);
			logger.debug("strSend:\n" + strSend);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			Response response = new Response();
			response.setResultCode(Constant.FALSE_CODE);
			response.setResultMessage(e.getMessage());
			strSend = JSON.toJSONString(response);
		}
		// 发送消息回客户端
		sendBack_UDP(strSend);
	}

	private void sendBack_UDP(String strSend) {
		byte[] sendBuf;
		DatagramPacket pSend;
		int lenSend;
		try {
			InetAddress addrClient = dgp.getAddress();
			int portClient = dgp.getPort();
			sendBuf = strSend.getBytes();
			lenSend = strSend.length();
			pSend = new DatagramPacket(sendBuf, lenSend, addrClient, portClient);
			s.send(pSend);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	String doClient(String msgReceived) throws Exception {
		String buffer = null;
		if(msgReceived.equals("please exit")){
			buffer = "ok";
			TCPServer.bExit = true;
			return buffer;
		}
		if (firewall == null) {
			throw new Exception("unSupport operator system");
		}
		if (msgReceived.contains(Constant.AddRuleToken)) {
			AddRuleRequest request = JSON.parseObject(msgReceived,
					AddRuleRequest.class);
			buffer = firewall.addRule(request);
		} else if (msgReceived.contains(Constant.GetRulesToken)) {
			GetRulesRequest request = JSON.parseObject(msgReceived,
					GetRulesRequest.class);
			buffer = firewall.getRules(request);
		} else if (msgReceived.contains(Constant.DelRuleToken)) {
			DeleteRuleRequest request = JSON.parseObject(msgReceived,
					DeleteRuleRequest.class);
			buffer = firewall.deleteRule(request);
		} else if (msgReceived.contains(Constant.GetDefaultRuleToken)) {
			GetDefaultRuleRequest request = JSON.parseObject(msgReceived,
					GetDefaultRuleRequest.class);
			buffer = firewall.getDefaultRule(request);
		}else {
			String msg = "unkown type request";
			throw new Exception(msg);
		}
		return buffer;
	}

}
