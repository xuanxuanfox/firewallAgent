package com.pkq.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author lei 2011-9-2
 */
public class StringUtils {

	/**
	 * 此函数会去掉字符串中间的空格，只适合本项目使用，不适合做为通用
	 * @param str
	 * @return
	 */
	public static String replaceBlank(String str) {
		String dest = "";
		if (str != null) {
			//--去掉特殊字符
			byte[] bs = {-95,-95};
			String ss = new String(bs);
			char cs = ' ';
			str = str.replace(ss.charAt(0), cs);
			//--去掉空格，换行，tab
			Pattern p = Pattern.compile("\\s*|\t|\r|\n"); 
			Matcher m = p.matcher(str);
			dest = m.replaceAll("");
			//dest = dest.trim();
		}
		return dest;
	}

	public static void main(String[] args) {
		System.out.println(StringUtils.replaceBlank("  just do it!   \n \r\n "));
	}

}
