package com.pkq.firewall.app;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.TimerTask;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import com.alibaba.fastjson.JSON;
import com.pkq.firewall.agent.FireWallOp;
import com.pkq.firewall.message.request.UpdateRequest;
import com.pkq.firewall.message.response.Response;
import com.pkq.util.SystemUtil;

public class UpdateTask extends TimerTask {
	Logger logger = LoggerFactory.getLogger(UpdateTask.class);
	FireWallOp firewall = null;

	public UpdateTask() {
		firewall = AgentApp.firewall;
	}

	public void run() {
		doUpdate();
	}

	void doUpdate() {
		try {
			String url = AgentApp.newestVersionUrl + "ostype=" + AgentApp.optype;
			logger.debug("UpdateTask.doUpdate(), url:" + url);
			String jsonString = getJsonString(url);
			logger.debug("UpdateTask.doUpdate(), http return jsonString:" + jsonString);

			// Map<String,Object> map =
			// (Map<String,Object>)JSON.parse(jsonString);
			UpdateRequest request = JSON.parseObject(jsonString,
					UpdateRequest.class);
			firewall.updateAgent(request);
		} catch (Exception e) {
			logger.error("exception:", e);
		}
	}

	protected String getJsonString(String urlPath) throws Exception {
		URL url = new URL(urlPath);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.connect();
		InputStream inputStream = connection.getInputStream();
		// 对应的字符编码转换
		Reader reader = new InputStreamReader(inputStream, "UTF-8");
		BufferedReader bufferedReader = new BufferedReader(reader);
		String str = null;
		StringBuffer sb = new StringBuffer();
		while ((str = bufferedReader.readLine()) != null) {
			sb.append(str);
		}
		reader.close();
		connection.disconnect();
		return sb.toString();
	}
	


}
