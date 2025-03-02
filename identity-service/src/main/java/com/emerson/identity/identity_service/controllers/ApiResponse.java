package com.emerson.identity.identity_service.controllers;

public class ApiResponse <T>{
    private String message;
    private boolean success;
    private T data;
    private ApiResponse(String message, boolean success, T data){
        this.message = message;
        this.success = success;
        this.data = data;
    }
    public static <T> ApiResponse<T> success(T data, String message){
        return new ApiResponse<>(message, true, data);
    }
    public static <T> ApiResponse<T> success(T data){
        return new ApiResponse<>("Success", true, data);
    }
    public static <T> ApiResponse<T> error(String message, T data){
        return new ApiResponse<>(message, false, data);
    }
    public static <T> ApiResponse<T> error(T data){
        return new ApiResponse<>("failed", false, data);
    }
}
