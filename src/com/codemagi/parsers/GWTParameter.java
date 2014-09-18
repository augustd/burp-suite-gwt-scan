package com.codemagi.parsers;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class GWTParameter {
    
    private String value;
    private int index;
    private boolean fuzzable = false;
    private GWTParameterType type;

    /**
     * Creates a new GWTParameter with a default type of NUMERIC.
     * 
     * @param value
     * @param fuzzable 
     */
    public GWTParameter(String value, boolean fuzzable) {
	this.value = value;
	this.fuzzable = fuzzable;
	this.type = GWTParameterType.NUMERIC;
    }

    public GWTParameter(String value, boolean fuzzable, GWTParameterType type) {
	this.value = value;
	this.fuzzable = fuzzable;
	this.type = type;
    }

    public String getValue() {
	return value;
    }

    public void setValue(String value) {
	this.value = value;
    }

    public int getIndex() {
	return index;
    }

    public void setIndex(int index) {
	this.index = index;
    }

    public boolean isFuzzable() {
	return fuzzable;
    }

    public void setFuzzable(boolean fuzzable) {
	this.fuzzable = fuzzable;
    }

    public GWTParameterType getType() {
	return type;
    }

    public void setType(GWTParameterType type) {
	this.type = type;
    }
    
}
