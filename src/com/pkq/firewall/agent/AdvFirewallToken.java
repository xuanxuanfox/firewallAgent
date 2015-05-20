package com.pkq.firewall.agent;

public class AdvFirewallToken {
	private static String[] tokens_OK = {"确定。"};
	private static String[] tokens_DEFAULTPOLICY = {"防火墙策略"};
	private static String[] tokens_GETRULE_REMOTEIP = {"远程 IP:"};
	private static String[] tokens_GETRULE_PROTOCOL = {"协议:"};
	private static String[] tokens_GETRULE_LOCALPORT = {"本地端口:"};
	private static String[] tokens_GETRULE_REMOTEPORT = {"远程端口:"};
	private static String[] tokens_GETRULE_ACTION = {"操作:"};
	public static String tokenNewLine = "\r\n";
	public static int TOKEN_TYPE_OK =0;
	public static int TOKEN_TYPE_DEFAULTPOLICY =1;
	public static int TOKEN_TYPE_GETRULE_REMOTEIP =2;
	public static int TOKEN_TYPE_GETRULE_PROTOCOL =3;
	public static int TOKEN_TYPE_GETRULE_LOCALPORT =4;
	public static int TOKEN_TYPE_GETRULE_REMOTEPORT =5;
	public static int TOKEN_TYPE_GETRULE_ACTION =6;
	
	public static String getToken(String message,int type){
		/*判断特征字符是中文还是英文*/
		String token=null;
		String[] tokens = null;
		if(TOKEN_TYPE_OK==type){
			tokens = tokens_OK;
		}else if(TOKEN_TYPE_DEFAULTPOLICY==type){
			tokens = tokens_DEFAULTPOLICY;
		}else if(TOKEN_TYPE_GETRULE_REMOTEIP==type){
			tokens = tokens_GETRULE_REMOTEIP;
		}else if(TOKEN_TYPE_GETRULE_PROTOCOL==type){
			tokens = tokens_GETRULE_PROTOCOL;
		}else if(TOKEN_TYPE_GETRULE_LOCALPORT==type){
			tokens = tokens_GETRULE_LOCALPORT;
		}else if(TOKEN_TYPE_GETRULE_REMOTEPORT==type){
			tokens = tokens_GETRULE_REMOTEPORT;
		}else if(TOKEN_TYPE_GETRULE_ACTION==type){
			tokens = tokens_GETRULE_ACTION;
		}
		for( int i=0;i<tokens.length;i++){
			if(message.indexOf(tokens[i])>=0){
				token=tokens[i];
				break;
			}
		}
		return token;
	}
		
}
