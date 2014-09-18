/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.codemagi.parsers;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author alla
 */
public class GWTParserTest {
    String request = "POST /whatever HTTP/1.1\r\n"+
"Host: berp005:2443\r\n"+
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0\r\n"+
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
"Accept-Language: en-us,en;q=0.5\r\n"+
"Accept-Encoding: gzip, deflate\r\n"+
"Connection: keep-alive\r\n"+
"Content-Type: text/x-gwt-rpc; charset=utf-8\r\n"+
"X-GWT-Permutation: C85D737C4CAAD1808B5DB1FC80C2A357\r\n"+
"X-GWT-Module-Base: https://whatever/whatever/\r\n"+
"Referer: https://whatever/whatever/\r\n"+
"Content-Length: 283\r\n"+
"Cookie: JSESSIONID=7ee5910385b04188edffa8302e0a\r\n"+
"Pragma: no-cache\r\n"+
"Cache-Control: no-cache\r\n\r\n"+
            "7|0|9|https://whatever/whatever|F5C1B07FE17F07C5229B34130145AD52|com.gremwell.test.whatever|whatever|java.lang.String/2004016611|java.lang.Long/4227064769|0\\!1|Oper|obfuscation|1|2|3|4|5|5|6|5|5|5|0|6|Q|7|8|9|\r\n";

    public GWTParserTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of parse method, of class GWTParser.
     */
    //@Test
    public void testParse() {
        System.out.println("testParse:");
        GWTParser instance = new GWTParser();
        instance.parse(request);
        assertEquals(7, instance.getVersion());
        assertEquals(0, instance.getFlag());
        assertEquals(9, instance.getStringTableSize());
        assertEquals(5, instance.getParametersNumber());
        /*
	for(int i =0; i<instance.getParametersNumber(); i++) {
            RequestParameter param = instance.getParameter(i);
            System.out.println(param.getType() + " = " + param.getValue());
        }*/
        assertEquals("obfuscation", instance.getParameter(4).getValue());

	/*
        int start = instance.getParameter(4).getStartOffset();
        System.out.println("Value start: " + start);
        int end = instance.getParameter(4).getEndOffset();
        System.out.println("Value end: " + end);
        System.out.println(request.substring(start));
        String substr = request.substring(start, end);
        assertEquals("obfuscation", substr);
	*/
    }

    String request2 = "POST /com.something.MyClass/gwtrpc/service HTTP/1.1\r\n" +
"Host: some.website.com\r\n" +
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
"Accept-Language: en-US,en;q=0.5\r\n" +
"Accept-Encoding: gzip, deflate\r\n" +
"DNT: 1\r\n" +
"Content-Type: text/x-gwt-rpc; charset=utf-8\r\n" +
"X-GWT-Permutation: 3B464280BDAA845B751E5BA57506E96F\r\n" +
"Content-Length: 309\r\n" +
"Connection: keep-alive\r\n" +
"Pragma: no-cache\r\n" +
"Cache-Control: no-cache\r\n" +
"\r\n" +
"7|0|9|https://www.something.com/com.something.MyClass/|4C36530F44562321E612D40FE92B3C74|com.something.gwtrpc.MyClass|CreateSession|java.lang.String/2004016611|java.util.List|joebob@nowhere.net|tycvbkjnlm;,|java.util.ArrayList/4159755760|1|2|3|4|4|5|5|5|6|0|7|8|9|0|";

    /**
     * Test of parse method, of class GWTParser.
     */
    @Test
    public void testParse2() {
        System.out.println("testParse2:");
        GWTParser instance = new GWTParser();
        instance.parse(request2);
        assertEquals(7, instance.getVersion());
        assertEquals(0, instance.getFlag());
        assertEquals(9, instance.getStringTableSize());
	
	assertEquals("https://www.something.com/com.something.MyClass/", instance.getServletUrl());
	assertEquals("4C36530F44562321E612D40FE92B3C74", instance.getStrongName());
	assertFalse(instance.hasXsrfToken());
	assertEquals("com.something.gwtrpc.MyClass", instance.getServiceClass());
	assertEquals("CreateSession", instance.getServiceMethod());
	
	System.out.println("Fuzz String: " + instance.getFuzzString());
        instance.printOffsets();
	
        assertEquals(4, instance.getParametersNumber());
	/*
        for(int i =0; i<instance.getParametersNumber(); i++) {
	    RequestParameter param = instance.getParameter(i);
            System.out.println(param.getType() + " = " + param.getValues());
        }*/
        assertEquals("tycvbkjnlm;,", instance.getParameter(2).getValue());

	/*
        int start = instance.getParameter(2).getStartOffset();
        System.out.println("Value start: " + start);
        int end = instance.getParameter(2).getEndOffset();
        System.out.println("Value end: " + end);
        System.out.println(request2.substring(start));
        String substr = request2.substring(start, end);
        assertEquals("tycvbkjnlm;,", substr);
	*/
    }
    
    String request3 = "\r\n" +
"\r\n" +
"7|0|38|https://www.something.com/com.something.MyClass/|4C36530F44562321E612D40FE92B3C74|com.something.gwtrpc.MyClass|GetProperties|java.lang.String/2004016611|I|java.util.List|java.util.ArrayList/4159755760|cms.topSignUpUrl|cms.topSignUpHeight|cms.topSignUpWidth|cms.bottomSignUpUrl|cms.bottomSignUpHeight|cms.bottomSignUpWidth|cms.rightSignUpUrl|cms.rightSignUpHeight|cms.rightSignUpWidth|cms.signUpCompleteUrl|cms.signUpCompleteHeight|cms.signUpCompleteWidth|cms.topSignInUrl|cms.topSignInHeight|cms.topSignInWidth|cms.bottomSignInUrl|cms.bottomSignInHeight|cms.bottomSignInWidth|cms.rightSignInUrl|cms.rightSignInHeight|cms.rightSignInWidth|cms.getStartedUrl|cms.getStartedHeight|cms.getStartedWidth|cms.headerUrl|cms.headerHeight|cms.headerWidth|cms.footerUrl|cms.footerHeight|cms.footerWidth|1|2|3|4|3|5|6|7|0|2663|8|30|5|9|5|10|5|11|5|12|5|13|5|14|5|15|5|16|5|17|5|18|5|19|5|20|5|21|5|22|5|23|5|24|5|25|5|26|5|27|5|28|5|29|5|30|5|31|5|32|5|33|5|34|5|35|5|36|5|37|5|38|";

    /**
     * Test of parse method, of class GWTParser.
     */
    @Test
    public void testParse3() {
        System.out.println("\ntestParse3:");
        GWTParser instance = new GWTParser();
        instance.parse(request3);
        assertEquals(7, instance.getVersion());
        assertEquals(0, instance.getFlag());
        assertEquals(38, instance.getStringTableSize());
	
	assertEquals("https://www.something.com/com.something.MyClass/", instance.getServletUrl());
	assertEquals("4C36530F44562321E612D40FE92B3C74", instance.getStrongName());
	assertFalse(instance.hasXsrfToken());
	assertEquals("com.something.gwtrpc.MyClass", instance.getServiceClass());
	assertEquals("GetProperties", instance.getServiceMethod());
	
	System.out.println("Fuzz String: " + instance.getFuzzString());
        instance.printOffsets();
	
        assertEquals(3, instance.getParametersNumber());
        /*
	for(int i =0; i<instance.getParametersNumber(); i++) {
	    RequestParameter param = instance.getParameter(i);
            System.out.println(param.getType() + " = " + param.getValues());
        }*/
	assertNull(instance.getParameter(0).getValue());
        assertEquals("2663", instance.getParameter(1).getValue());

	/*
        int start = instance.getParameter(1).getStartOffset();
        System.out.println("Value start: " + start);
        int end = instance.getParameter(1).getEndOffset();
        System.out.println("Value end: " + end);
        System.out.println(request3.substring(start));
        String substr = request3.substring(start, end);
        assertEquals("2663", substr);
	*/
    }
    
    String request4 = "\r\n\r\n7|0|29|https://www.something.com/com.something.MyClass/|4C36530F44562321E612D40FE92B3C74|com.demandreports.wb.client.gwtrpc.WorkbenchService|CreateTenant|java.lang.String/2004016611|com.demandreports.accesscontrol.Tenant/3611844405|com.demandreports.accesscontrol.TenantUser/3185185105|com.demandreports.accesscontrol.User/3693044902|Z|https://workbench.connectioncloud.com/?page=accountActivation|22bb|com.demandreports.util.PropertyList/3137720469|com.demandreports.util.Property/1762551962|firstSignIn|true|newTenant|newUser|com.demandreports.accesscontrol.TenantUser$TenantUserStatus/3971456614|adetlefsen@appsecconsulting.com|33cc|44dd|java.util.ArrayList/4159755760|title|55ee|phoneNumber|66ff|address|77gg|timeZoneId|1|2|3|4|7|5|5|6|7|8|5|9|0|10|6|0|0|0|-1|0|0|-1|0|600|11|0|0|0|12|0|0|60|0|0|0|0|0|0|7|0|0|12|0|-1|12|3|13|14|15|13|16|15|13|17|15|0|0|18|0|0|0|19|0|0|0|0|8|0|0|20|21|22|3|13|23|24|13|25|26|13|27|28|29|19|0|1|";
    
        /**
     * Test of parse method, of class GWTParser.
     */
    @Test
    public void testParse4() {
        System.out.println("\ntestParse4:");
        GWTParser instance = new GWTParser();
        instance.parse(request4);
        assertEquals(7, instance.getVersion());
        assertEquals(0, instance.getFlag());
        assertEquals(29, instance.getStringTableSize());
	
	System.out.println("Fuzz String: " + instance.getFuzzString());
        instance.printOffsets();
	
        assertEquals("https://www.something.com/com.something.MyClass/", instance.getServletUrl());
	assertEquals("4C36530F44562321E612D40FE92B3C74", instance.getStrongName());
	assertFalse(instance.hasXsrfToken());
	assertEquals("com.something.gwtrpc.MyClass", instance.getServiceClass());
	assertEquals("CreateTenant", instance.getServiceMethod());
	
	assertEquals(7, instance.getParametersNumber());
        /*
	for(int i =0; i<instance.getParametersNumber(); i++) {
	    RequestParameter param = instance.getParameter(i);
            System.out.println(param.getType() + " = " + param.getValues());
        }
	*/
	
	/*
	assertNull(instance.getParameter(0).getValue());
        assertEquals("2663", instance.getParameter(1).getValue());

        int start = instance.getParameter(1).getStartOffset();
        System.out.println("Value start: " + start);
        int end = instance.getParameter(1).getEndOffset();
        System.out.println("Value end: " + end);
        System.out.println(request4.substring(start));
        String substr = request4.substring(start, end);
        assertEquals("2663", substr);
	*/
    }
    
}
