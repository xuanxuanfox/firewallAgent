package com.pkq.firewall.app;

import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.pkq.firewall.app.UDPServer;

public class AgentApp {
	Logger logger = LoggerFactory.getLogger(AgentApp.class); 
	
	public static void main(String[] args) {
		AgentApp app = new AgentApp();
		app.runApp();
	}

	void runApp() {
		Properties prop = new Properties();
		try {
			String pn = "/config.properties";
			InputStream is = this.getClass().getResourceAsStream(pn);
			prop.load(is);
			is.close();
			int port = Integer.parseInt(prop.getProperty("port").trim());
			logger.info("listen port:"+port);
			UDPServer dgs = new UDPServer(port);
			dgs.listen();
		} catch (Exception e) {
			//e.getMessage();
			logger.error(e.getMessage(),e);
			return;
		}
		

	}

}
