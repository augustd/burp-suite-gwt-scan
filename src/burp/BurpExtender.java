package burp;

import com.codemagi.parsers.GWTParser;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

/**
 * GWT Scan
 * 
 * Burp Suite Extension to parse GWT (Google Web Toolkit) requests and identify insertion points. 
 * Identified GWT insertion points are automatically used in Scanner and pre-identified insertion 
 * points can be used in Intruder. 
 * 
 * @author August Detlefsen <augustd at codemagi dot com>
 * @inspiration alla http://www.gremwell.com/burp_plugin_for_scanning_gwt_and_json
 */
public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider, IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private OutputStream error;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
	// keep a reference to our callbacks object
	this.callbacks = callbacks;
	
	// obtain an extension helpers object
	helpers = callbacks.getHelpers();
	
	// set our extension name
	callbacks.setExtensionName("GWT Scan");
	
	// register ourselves as a scanner insertion point provider
	callbacks.registerScannerInsertionPointProvider(this);
	
	// register ourselves as a Context Menu Factory
	callbacks.registerContextMenuFactory(this);

	//get the output stream for info messages
	output = callbacks.getStdout();
	
	//get the error stream for error messages
	OutputStream error = callbacks.getStderr();
	
	println("Loaded GWT Scan");
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
	byte[] request = baseRequestResponse.getRequest();
	String requestAsString = new String(request);

	GWTParser parser = new GWTParser();
	parser.parse(requestAsString);

	List<int[]> insertionPointOffsets = parser.getOffsets();
	int bodyStart = parser.getBodyStart();

	if (insertionPointOffsets != null && !insertionPointOffsets.isEmpty()) {
	    List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>(insertionPointOffsets.size());

	    for (int[] offset : insertionPointOffsets) {
		println("Found GWT insertion point: " + offset[0] + ", " + offset[1]);
		IScannerInsertionPoint point = helpers.makeScannerInsertionPoint("GWT Insertion Point", request, 
										  offset[0] - bodyStart, 
										  offset[1] - bodyStart);
		insertionPoints.add(point);
	    }
	    return insertionPoints;
	}
	return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
	
	//get selected requests from the invocation
	IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();
	
	//create clickable menu item
	JMenuItem item = new JMenuItem("Send GWT request(s) to Intruder");
	item.addActionListener(new MenuItemListener(ihrrs));

	//return a Collection of menu items
	List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
	menuItems.add(item);
	
	return menuItems;
    }
    
    class MenuItemListener implements ActionListener {
	
	private IHttpRequestResponse[] ihrrs;
	
	public MenuItemListener(IHttpRequestResponse[] ihrrs) {
	    this.ihrrs = ihrrs;
	}
	
	public void actionPerformed(ActionEvent ae) {
	    println("menu item clicked!");
	    sendGWTToIntruder(ihrrs);
	}
    }
    
    public void sendGWTToIntruder(IHttpRequestResponse[] ihrrs) {
	
	for (IHttpRequestResponse baseRequestResponse : ihrrs) { 
	    
	    IHttpService service = baseRequestResponse.getHttpService();
	    
	    try {
		//parse the request
		byte[] request = baseRequestResponse.getRequest();
		String requestAsString = new String(request);
		GWTParser parser = new GWTParser();
		parser.parse(requestAsString);
		
		List<int[]> insertionPointOffsets = parser.getOffsets();
		
		if (insertionPointOffsets != null && !insertionPointOffsets.isEmpty()) {
		    // Send GWT request to Intruder
		    callbacks.sendToIntruder(service.getHost(), service.getPort(), service.getProtocol().equals("https"), 
					     request, insertionPointOffsets);
		    baseRequestResponse.setComment("GWT: " + parser.getServiceMethod() + " " + baseRequestResponse.getComment());
		}
	    } catch (Exception ex) {
		ex.printStackTrace();
		callbacks.issueAlert("Caught " + ex + " while reading HTTP response: " + ex.getLocalizedMessage());
	    }
	}
    }

    private void println(String toPrint) {
	try {
	    output.write(toPrint.getBytes());
	    output.write("\n".getBytes());
	    output.flush();
	} catch (IOException ioe) {
	    printStackTrace(ioe);
	} 
    }
    
    private void printStackTrace(Exception e) {
	e.printStackTrace(new PrintStream(error));
    } 
}