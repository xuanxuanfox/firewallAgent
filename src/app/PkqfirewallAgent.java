package app;

import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pkq.network.UDPServer;

public class PkqfirewallAgent {
	Logger logger = LoggerFactory.getLogger(PkqfirewallAgent.class); 
	
	public static void main(String[] args) {
		PkqfirewallAgent app = new PkqfirewallAgent();
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
