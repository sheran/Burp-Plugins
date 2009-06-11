import java.util.regex.Matcher;
import java.util.regex.Pattern;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;


public class BurpExtender implements IBurpExtender {

	public burp.IBurpExtenderCallbacks callBacks;
	
	public void applicationClosing() {
	}

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callBacks = callbacks;
	}

	public void setCommandLineArgs(String[] cla) {	
	}
	
	public byte[] processProxyMessage(
			int messageReference, 
			boolean messageIsRequest, 
			String remoteHost,
			int remotePort, 
			boolean serviceIsHttps, 
			String httpMethod, 
			String url, 
			String resourceType,
			String statusCode, 
			String responseContentType, 
			byte[] message, 
			int[] action) 
	{
		
		byte[] firstRequest;
		byte[] nextRequest;
		String initialCookies = "";
		
		if(!messageIsRequest){
			try{
				if(isBigIPError(message)){
					callBacks.issueAlert("Attempting to re-login...");
					firstRequest = new String("[Enter GET Request Here, one string seperate with '\r\n']").getBytes();
					nextRequest = new String("[Enter POST Request Here, one string seperate with '\r\n'").getBytes();
					byte[] firstResp = callBacks.makeHttpRequest(remoteHost, remotePort, serviceIsHttps, firstRequest);
					initialCookies = grabCookies(firstResp);
					byte[] interimReq = buildRequest(initialCookies,nextRequest);
					message = callBacks.makeHttpRequest(remoteHost, remotePort, serviceIsHttps, interimReq);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return message;
	}

	private String grabCookies(byte[] getRequest){
		String getReq = new String(getRequest);		
		String regEx = "Set-Cookie:\\s(.*?);";
		Pattern pattern = Pattern.compile(regEx, Pattern.DOTALL | Pattern.MULTILINE);
		Matcher matcher = pattern.matcher(getReq);
		StringBuilder cookies = new StringBuilder();
		cookies.append("Cookie: ");
		while(matcher.find()){
			cookies.append(matcher.group(1)+"; ");
		}
		cookies.append("\r\n");
		return cookies.toString();
	}
		
	private byte[] buildRequest(String cookies, byte[] postRequest){
		String[] carvedPost = {};
		String postReq = new String(postRequest);
		carvedPost = postReq.split("\r\n\r\n");
		postReq = carvedPost[0]+"\r\nContent-Length: "+carvedPost[1].length()+"\r\n\r\n"+carvedPost[1];
		StringBuffer finalReq = new StringBuffer();
		String regEx = "Cookie:\\s(.*?)\r\n";
		Pattern pattern = Pattern.compile(regEx, Pattern.DOTALL | Pattern.MULTILINE);
		Matcher matcher = pattern.matcher(postReq);	
		while(matcher.find()){			
			matcher.group();
			matcher.appendReplacement(finalReq,cookies.toString());
		}
		matcher.appendTail(finalReq);				
		return finalReq.toString().getBytes();
	}
	
	private boolean isBigIPError(byte[] msg){
		String message = new String(msg);
		boolean result =false;
		try{
			String regEx = "[Enter your RegEx for the Error Page here]";
			Pattern pattern = Pattern.compile(regEx,Pattern.DOTALL|Pattern.MULTILINE);
			Matcher matcher = pattern.matcher(message);
			if(matcher.matches()){
				callBacks.issueAlert("Received error from F5 Big-IP!");
				result = true;
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}
}
