package test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pkq.util.FileOp;
import app.Constant;
import app.Rule;
import app.firewall.IPTables;
import app.message.request.AddRuleRequest;
import app.message.request.GetDefaultRuleRequest;
import app.message.request.GetRulesRequest;
import app.message.response.GetRulesResponse;

public class TestIptables {
	static Logger logger = LoggerFactory.getLogger(IPTables.class);
	 public static void main(String[] args){
		 testAll();
	 }
	 
	 static void testAll(){
		 //testIptables_getDefaultRule();
		 //testIptables_AddRule();
		 testIptables_GetRules();
		 //testgetIptables_parseRule();
		//testgetIptables_parseRemotePort();
		 //testIptables_parseGetRulesResponse();
	}
	
	 static void testIptables_AddRule(){
			IPTables o = new IPTables();
			try{
				AddRuleRequest request = new AddRuleRequest();
				Rule rule = new Rule();
				rule.setDirection("inbound");
				rule.setAction("allow");
				rule.setProtocol("tcp");
				rule.setRemoteIp("192.168.1.100");
				rule.setRemotePort("3306");
				//rule.setRemotePort("8080,80");
				request.setRule(rule);
				String ret = o.addRule(request);
				System.out.println(ret);
			}catch(Exception ex){
				logger.error(ex.getMessage());
			}
		}

	 static void testIptables_GetRules(){
			IPTables o = new IPTables();
			try{
				GetRulesRequest request = new GetRulesRequest();
				//request.setDirection(Constant.Direction_out);
				request.setDirection(Constant.Direction_in);
				request.setStartRow(1);
				request.setLimit(10);
				String ret = o.getRules(request);
				System.out.println(ret);
			}catch(Exception ex){
				logger.error(ex.getMessage());
			}
		}


	 static void testIptables_parseGetRulesResponse(){
			IPTables o = new IPTables();
			String message;
			String fileName="F:\\work\\工程\\myself\\防火墙集中管理平台\\iptables - 副本.txt";
			try{
				message = FileOp.readTextFile(fileName);
				int start = 1; 
				int limit = 100;
				GetRulesResponse response = o.parseGetRulesResponse( "inbound",start,  limit, message);
				
				message ="";
				
			}catch(Exception ex){
				logger.error(ex.getMessage());
			}
		}
	 
	 static void testIptables_getDefaultRule(){
		IPTables o = new IPTables();
		try{
			GetDefaultRuleRequest request = new GetDefaultRuleRequest();
			request.setDirection("inbound");
			String ret = o.getDefaultRule(request);
			System.out.println(ret);
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}
	 
	 static void testgetIptables_parseRule(){
			IPTables o = new IPTables();
			String message;
			try{
				//message = "1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:22 state NEW,ESTABLISHED";
				//message = "1    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:888";
				//message = "2    ACCEPT     tcp  --  0.0.0.0/0            192.168.1.101       multiport dports 3306,3307"; 
				//message = "10   ACCEPT     tcp  --  0.0.0.0/0            192.168.1.101       multiport dports 3306,3307 state NEW,ESTABLISHED"; 
				//message = "6    ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0";  //特殊规则，程序应该忽略之
				message = "5    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           state RELATED,ESTABLISHED";  //特殊规则，程序应该忽略之
				Rule rule = o.parseInputRule(message);
				System.out.println(rule);

				
			}catch(Exception ex){
				ex.printStackTrace();
			}
		}

}
