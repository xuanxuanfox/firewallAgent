package app;

public class Constant {
	public Constant(){}
	static final public String AddRule = "a";
	static final public String AddRuleToken = "msgType:"+AddRule;
	//---------
	static final public String GetRulesRequest = "g";
	static final public String GetRulesToken = "msgType:"+GetRulesRequest;
	//---------
	static final public String GetDefaultRuleRequest = "gd";
	static final public String GetDefaultRuleToken = "msgType:"+GetDefaultRuleRequest;
	//---------
	static final public String DelRule = "d";
	static final public String DelRuleToken = "msgType:"+DelRule;
	//---------
	static final public String Action_allow = "allow";
	static final public String Action_deny = "deny";
	//---------
	static final public String Direction_in = "inbound";
	static final public String Direction_out = "outbound";
	//---------
	public final static int SUCESS_CODE=0; 
	public final static String SUCESS_MESSAGE="sucess"; 
	public final static int FALSE_CODE=-1; 

}
