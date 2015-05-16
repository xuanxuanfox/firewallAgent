package test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pkq.firewall.agent.AdvFirewall;
import com.pkq.firewall.agent.IPTables;
import com.pkq.firewall.common.Constant;
import com.pkq.firewall.message.request.AddRuleRequest;
import com.pkq.firewall.message.request.GetDefaultRuleRequest;
import com.pkq.firewall.message.request.GetRulesRequest;
import com.pkq.firewall.model.Rule;

public class TestAdvFirewall {
	static Logger logger = LoggerFactory.getLogger(TestAdvFirewall.class);
	 public static void main(String[] args){
		 testAll();
	 }
	 
	 static void testAll(){
		 testIptables_getDefaultRule();
		 //testIptables_AddRule();
		 //testGetRules();
		 //testgetIptables_parseRule();
		//testgetIptables_parseRemotePort();
		 //testIptables_parseGetRulesResponse();
	}
	 
	 static void testIptables_getDefaultRule(){
		 AdvFirewall o = new AdvFirewall();
			try{
				GetDefaultRuleRequest request = new GetDefaultRuleRequest();
				request.setDirection("inbound");
				String ret = o.getDefaultRule(request);
				System.out.println(ret);
			}catch(Exception ex){
				ex.printStackTrace();
			}
		}

	 static void testGetRules(){
		 AdvFirewall o = new AdvFirewall();
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


}
