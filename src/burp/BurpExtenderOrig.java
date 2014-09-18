package burp;

import com.codemagi.parsers.GWTParser;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 * @inspiration alla http://www.gremwell.com/burp_plugin_for_scanning_gwt_and_json
 */
public class BurpExtenderOrig implements IBurpExtender, IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
	// keep a reference to our callbacks object
	this.callbacks = callbacks;
	
	// obtain an extension helpers object
	helpers = callbacks.getHelpers();
	
	// set our extension name
	callbacks.setExtensionName("GWT Scan");
	
	// register ourselves as a Context Menu Factory
	callbacks.registerContextMenuFactory(this);

	//get the menuItems stream for info messages
	output = callbacks.getStdout();
	
	println("Loaded GWT Scan");
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
	println("createMenuItems() invocation: " + invocation);
	
	//get information from the invocation
	IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();
	println(ihrrs.length + " requests selected");
	
	List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
	
	JMenuItem item = new JMenuItem("Actively scan GWT request(s)");
	item.addActionListener(new MenuItemListener(ihrrs));
	menuItems.add(item);
	
	return menuItems;
    }
    
    public void launchScan(IHttpRequestResponse[] ihrrs) {
	
	for (IHttpRequestResponse baseRequestResponse : ihrrs) { 
	    
	    IHttpService service = baseRequestResponse.getHttpService();

	    //get the URL of the requst
	    URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
	    println("Parsing for GWT request: " + url.toString());
	    
	    try {
		byte[] request = baseRequestResponse.getRequest();
		String requestAsString = new String(request);
		println(requestAsString);
		
		GWTParser parser = new GWTParser();
		parser.parse(requestAsString);
		
		List<int[]> insertionPointOffsets = parser.getOffsets();
		
		if (insertionPointOffsets == null || insertionPointOffsets.isEmpty()) {
		    println("    No insertion points found!");
		} else {
		    println("    Launching active scan of GWT request!");
		    callbacks.doActiveScan(service.getHost(), service.getPort(), service.getProtocol().equals("https"), request, insertionPointOffsets);
		    baseRequestResponse.setComment("GWT: " + parser.getServiceMethod() + " " + baseRequestResponse.getComment());
		}
	    } catch (Exception ex) {
		ex.printStackTrace();
		callbacks.issueAlert("Caught " + ex + " while reading HTTP response: " + ex.getLocalizedMessage());
	    }
	}
    }
    
    private List<int[]> parseRequest(String request) {
	GWTParser parser = new GWTParser();
	parser.parse(request);

	List<int[]> insertionPointOffsets = parser.getOffsets();
	parser.printOffsets();
	
	if (insertionPointOffsets.isEmpty()) {
	    return null;
	} else {
	    return insertionPointOffsets;
	}
    }
    
    class MenuItemListener implements ActionListener {
	
	private IHttpRequestResponse[] ihrrs;
	
	public MenuItemListener(IHttpRequestResponse[] ihrrs) {
	    this.ihrrs = ihrrs;
	}
	
	public void actionPerformed(ActionEvent ae) {
	    println("menu item clicked!");
	    launchScan(ihrrs);
	}
    }
    
    private void println(String toPrint) {
	try {
	    output.write(toPrint.getBytes());
	    output.write("\n".getBytes());
	    output.flush();
	} catch (IOException ioe) {
	    ioe.printStackTrace();
	} 
    }
}