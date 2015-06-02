package com.pkq.firewall.app;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TCPServer {
	int port = 5114;  //默认监听端口
	int receiveBufferSize = 1024; //默认接收缓冲区大小
	public static boolean bExit= false;
	Logger logger = LoggerFactory.getLogger(UDPServer.class); 
	
	public TCPServer(int port){
		this.port = port;
	}
	
	public void listen() {
		try {
			ServerSocket server = new ServerSocket(port);
			logger.info("listening ...");
			byte[] data = new byte[receiveBufferSize];
			while (!bExit) {
				Socket connection = server.accept();
				WorkThread wh = new WorkThread(connection);	
				//new Thread(wh).start();	
				//wh.start();
				wh.run();
			}
		} catch (Exception e) {
			logger.error(e.getMessage(),e);
		}
	}
}
