package com.pkq.firewall.app;

import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.util.Properties;
import java.util.Timer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pkq.firewall.agent.AdvFirewall;
import com.pkq.firewall.agent.FireWallOp;
import com.pkq.firewall.agent.IPTables;
import com.pkq.firewall.app.UDPServer;
import com.pkq.firewall.common.Constant;
import com.pkq.util.FileOp;
import com.pkq.util.OSinfo;

public class AgentApp {
	Logger logger = LoggerFactory.getLogger(AgentApp.class); 
	public static String version = "1.0";
	public static int versionIndex = 1;
	public static String optype="";
	public static FireWallOp firewall = null;
	//----------
	public static int port;
	
	
	public static void main(String[] args) {
		AgentApp app = new AgentApp();
		String pidFile = "pf.pid";
		String versionFile = "pf.version";
		app.init();
		String pid = app.getPid();
		String versionTag = String.format("%d,%s", versionIndex,version);
		try{
			FileOp.writeToTextFile(pidFile,pid);
			FileOp.writeToTextFile(versionFile,versionTag);
		}catch(Exception ex){
			ex.printStackTrace();
		}
		app.runApp();
	}
	
	//初始化
	void init() {
		//获取操作系统类型
		if (OSinfo.isWindows()) {
			optype = Constant.Optype_windows;
		} else if (OSinfo.isLinux()) {
			optype = Constant.Optype_linux;
		} else {
		}
		if (OSinfo.isWindows()) {
			firewall = new AdvFirewall();
		} else if (OSinfo.isLinux()) {
			firewall = new IPTables();
		} else {
			firewall = null;
		}
	}

	//应用主函数
	void runApp() {
		Properties prop = new Properties();
		try {
			String logmsg;
			String pn = "/config.properties";
			InputStream is = this.getClass().getResourceAsStream(pn);
			prop.load(is);
			is.close();
			port = Integer.parseInt(prop.getProperty("port").trim());
			logmsg = String.format("listen port:%d", port);
			logger.info(logmsg);
			//----------- 监听
			//UDPServer dgs = new UDPServer(port);
			TCPServer dgs = new TCPServer(port);
			dgs.listen();
			
		} catch (Exception e) {
			//e.getMessage();
			logger.error(e.getMessage(),e);
			return;
		}
	}
	
	/**
	 * 获取进程号
	 * @return
	 */
	String getPid(){
		String name = ManagementFactory.getRuntimeMXBean().getName();  
		System.out.println(name);  
		// get pid  
		String pid = name.split("@")[0];  
		//System.out.println("Pid is:" + pid);
		return pid;
	}

}
