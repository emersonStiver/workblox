package com.emerson.identity.identity_service.entities.enums;

public enum MFAMethod {
    EMAIL("Email"), QRCODE("Authenticator");
    private String mfaMethodName;
    MFAMethod(String methodName){
        this.mfaMethodName = methodName;
    }
    public String getMethodName(){
        return this.mfaMethodName;
    }
}
