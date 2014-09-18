package com.codemagi.parsers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 * @inspiration 'alla' at Gremwell's Blog  http://www.gremwell.com/burp_plugin_for_scanning_gwt_and_json
 */
public class GWTParser {

    private String gwtRequest;  //the GWT RPC request
    private int bodyStart;	//the start of the GWT RPC in the request body

    private int version;
    private int flag;
    private int stringTableSize;
    private String servletUrl;
    private String strongName;
    
    private String xsrfTokenClass;
    private String xsrfToken;
    
    private String serviceClass;
    private String serviceMethod;

    private String[] split;
    private String[] stringTable;
    private String[] payload;

    //List containing the parsed GWT RPC parameters 
    private List<GWTParameter> parameters = new ArrayList<GWTParameter>();
    
    private int parametersNumber;
    
    private boolean hasXsrfToken = false;
    
    public static final int STRING_TABLE_OFFSET = 3;
    public static final Set<String> PRIMITIVE_TYPES = new HashSet<String>();
    static {
	PRIMITIVE_TYPES.add("Z");
	PRIMITIVE_TYPES.add("B");
	PRIMITIVE_TYPES.add("C");
	PRIMITIVE_TYPES.add("S");
	PRIMITIVE_TYPES.add("I");
	PRIMITIVE_TYPES.add("J");
	PRIMITIVE_TYPES.add("F");
	PRIMITIVE_TYPES.add("D");
	PRIMITIVE_TYPES.add("java.util.List");  //List is obviously not a primitive type, but it is here for convenience
    }

    private static final Pattern CLASS_NAME = Pattern.compile("[A-Za-z\\.$]+/[0-9]+");
    
    public void parse(String request) {
	//find where the GWT RPC call starts in the HTTP request
        bodyStart = request.indexOf("\r\n\r\n") + 4;
	
	//extract just the GWT RPC call
        gwtRequest = request.substring(bodyStart);
        
	//does the body include an Xsrf token? 
	hasXsrfToken = gwtRequest.indexOf("XsrfToken") > 0;
	
	//Use 6 is XSRF token is included, 4 otherwise
	int parameterOffset = 4;
	if (hasXsrfToken) parameterOffset = 6;
	
	//split the request body on the pipe character
        split = gwtRequest.split("\\|");
	
	//parse the GWT header
        version = Integer.parseInt(split[0]);
	parameters.add(new GWTParameter(split[0], false));

        flag = Integer.parseInt(split[1]);
        parameters.add(new GWTParameter(split[1], false));
        
	stringTableSize = Integer.parseInt(split[2]);
	parameters.add(new GWTParameter(split[2], false));
        
	//parse the string table
	stringTable = new String[stringTableSize];
        for (int i = 0; i < stringTableSize; i++) {
            stringTable[i] = split[STRING_TABLE_OFFSET + i];
        }
	System.out.println("stringTable: " + Arrays.toString(stringTable));
	
	//parse the payload table
	int payloadSize = split.length - stringTableSize - STRING_TABLE_OFFSET;
	payload = new String[payloadSize];
	for (int i = 0; i < payloadSize; i++) {
            payload[i] = split[STRING_TABLE_OFFSET + stringTableSize + i];
        }
	System.out.println("payload: " + Arrays.toString(payload));
	
        //the first two entries of the String table are the servlet name and the strong name
	servletUrl = stringTable[0];
	parameters.add(new GWTParameter(servletUrl, false, GWTParameterType.STRING));
        
	strongName = stringTable[1];
	parameters.add(new GWTParameter(strongName, false, GWTParameterType.STRING));
        
	//if the request includes an Xsrf token, it will be at positions 2-3
	//otherwise, the service class and method will be there  
	if (hasXsrfToken) {
	    xsrfTokenClass = stringTable[2];
	    parameters.add(new GWTParameter(xsrfTokenClass, false, GWTParameterType.STRING));
	    
	    xsrfToken = stringTable[3];
	    parameters.add(new GWTParameter(xsrfToken, false, GWTParameterType.STRING));
	    
	    serviceClass = stringTable[4];
	    parameters.add(new GWTParameter(serviceClass, false, GWTParameterType.STRING));
	    
	    serviceMethod = stringTable[5];
	    parameters.add(new GWTParameter(serviceMethod, false, GWTParameterType.STRING));
	    
	} else {
	    serviceClass = stringTable[2];
	    parameters.add(new GWTParameter(serviceClass, false, GWTParameterType.STRING));
	    
	    serviceMethod = stringTable[3];
	    parameters.add(new GWTParameter(serviceMethod, false, GWTParameterType.STRING));
	}
	
	//the index of the end of the string table 
	int endOfStringTable = STRING_TABLE_OFFSET + stringTableSize + parameterOffset;
	System.out.println("endOfStringTable: " + endOfStringTable);
	
	//the number of parameters passed in the request
        parametersNumber = Integer.parseInt(split[endOfStringTable]);
	System.out.println("parametersNumber: " + parametersNumber);
	
	//fuzz each element of the string table that is not a class name 
	//or a recognized primitive abbreviation
	for (int i = STRING_TABLE_OFFSET + parameterOffset; i < STRING_TABLE_OFFSET + stringTableSize; i++) {
	    String stringTableEntry = split[i];
	    System.out.println("stringTableEntry: " + stringTableEntry);
	    
	    Matcher matcher = CLASS_NAME.matcher(stringTableEntry);
	    if (matcher.matches() || PRIMITIVE_TYPES.contains(stringTableEntry)) {
		System.out.println("  -CLASS! Skipping...");
		parameters.add(new GWTParameter(stringTableEntry, false, GWTParameterType.STRING));
		continue;
	    }
	    
	    //this is fuzzable!
	    parameters.add(new GWTParameter(stringTableEntry, true, GWTParameterType.STRING));
	}
	
	//fuzz each element of the payload table that does not reference a 
	//value in the string table
	for (int i = STRING_TABLE_OFFSET + stringTableSize; i < split.length; i++) {
	    String payloadEntry = split[i];
	    System.out.println("payloadEntry: " + payloadEntry);
	    
	    //the first 4 elements of the payload reference entries in the string table: 
	    //URL, strong name, service and method - NOT FUZZABLE
	    //the 5th entry is the number of parameters - NOT FUZZABLE
	    if (i < STRING_TABLE_OFFSET + stringTableSize + 5) {
		parameters.add(new GWTParameter(payloadEntry, false));
		continue;
	    }
	    
	    //payload table can contain chars and base64 encoded numbers, hence the try 
	    try {
		int payloadValue = Integer.parseInt(payloadEntry);
		
		if (5 <= payloadValue && payloadValue <= stringTable.length) {
		    System.out.println("  -REFERENCE! Skipping...");
		    parameters.add(new GWTParameter(payloadEntry, false));
		    continue;
		}	    
	    } catch (NumberFormatException nfe) {
		//do nothing. If the value failed parsing we definitely want to fuzz it
		System.out.println("  --NOT PARSEABLE! Adding to fuzz list");
		//TODO add %s to fuzz string here
	    }
	    
	    //this is fuzzable!
	    parameters.add(new GWTParameter(payloadEntry, true));
	}

    }

    public int getBodyStart() {
	return bodyStart;
    }
    
    public int getFlag() {
        return flag;
    }

    public String getGwtRequest() {
        return gwtRequest;
    }

    public GWTParameter getParameter(int index) {
        return parameters.get(index);
    }

    public int getParametersNumber() {
        return parametersNumber;
    }

    public String[] getStringTable() {
        return stringTable;
    }

    public int getStringTableSize() {
        return stringTableSize;
    }

    public int getVersion() {
        return version;
    }

    public String getServletUrl() {
	return servletUrl;
    }

    public String getStrongName() {
	return strongName;
    }

    public String getXsrfTokenClass() {
	return xsrfTokenClass;
    }

    public String getXsrfToken() {
	return xsrfToken;
    }

    public String getServiceClass() {
	return serviceClass;
    }

    public String getServiceMethod() {
	return serviceMethod;
    }

    public boolean hasXsrfToken() {
	return hasXsrfToken;
    }

    public List<int[]> getOffsets() {
	System.out.println("getOffsets() -----------------------");
	List<int[]> output = new ArrayList<int[]>();
	StringBuilder builder = new StringBuilder();
	System.out.println("Body start: " + bodyStart);
	
	for (GWTParameter parameter : parameters) {
	    System.out.println("    parameter: fuzzable: " + parameter.isFuzzable() + " value: " + parameter.getValue());
	    int[] offset = new int[2];
	    if (parameter.isFuzzable()) {
		offset[0] = bodyStart + builder.length();
	    }
	    builder.append(parameter.getValue());
	    if (parameter.isFuzzable()) {
		offset[1] = bodyStart + builder.length();
		output.add(offset);
	    }
	    System.out.println("                offsets: " + offset[0] + "," + offset[1]);
	    builder.append("|");
	}
	
	return output;
    }

    public String getFuzzString() {
	System.out.println("getFuzzString() -----------------------");
	StringBuilder builder = new StringBuilder();
	
	for (GWTParameter parameter : parameters) {
	    System.out.println("    parameter: fuzzable: " + parameter.isFuzzable() + " value: " + parameter.getValue());
	
	    if (parameter.isFuzzable()) {
		if (GWTParameterType.NUMERIC.equals(parameter.getType())) {
		    builder.append("%d");
		} else {
		    builder.append("%s");
		}
	    } else {
		builder.append(parameter.getValue());
	    }
	    builder.append("|");
	}
	
	return builder.toString();
    }
    
    public void printOffsets() {
	List<int[]> offsets = this.getOffsets();
	System.out.print("OFFSETS: ");
	for (int[] offset : offsets) {
	    System.out.print("[");
	    boolean first = true;
	    for (int i : offset) {
		if (!first) {
		    System.out.print(",");
		}
		System.out.print(i);
		first = false;
	    }
	    System.out.print("],");
	}
	System.out.println("");
    }

}
