package app.message.response;

import app.Constant;

public class Response {
	int resultCode=Constant.SUCESS_CODE;
	String resultMessage=Constant.SUCESS_MESSAGE;
	
	public int getResultCode() {
		return resultCode;
	}
	public void setResultCode(int resultCode) {
		this.resultCode = resultCode;
	}
	public String getResultMessage() {
		return resultMessage;
	}
	public void setResultMessage(String resultMessage) {
		this.resultMessage = resultMessage;
	}

}
