package com.pkq.firewall.app;

import java.io.*;
import java.net.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.pkq.firewall.app.WorkThread;

public class UDPServer {
	int port = 5114;  //默认监听端口
	int receiveBufferSize = 1024; //默认接收缓冲区大小
	Logger logger = LoggerFactory.getLogger(UDPServer.class); 
	
	public UDPServer(int port){
		this.port = port;
	}
	public void listen() {
		try {
			DatagramSocket s = new DatagramSocket(port);
			logger.info("listening ...");
			byte[] data = new byte[receiveBufferSize];
			DatagramPacket dgp = new DatagramPacket(data, data.length);
			
			while (true) {
				s.receive(dgp);
				//String msgReceived = new String(dgp.getData(), 0, dgp.getLength());
				//logger.debug("recv msg:" + msgReceived);
				WorkThread wh = new WorkThread(s, dgp);	
				//new Thread(wh).start();	
				wh.start();
				//wh.run();
			}
		} catch (Exception e) {
			logger.error(e.getMessage(),e);
		}
	}

}
