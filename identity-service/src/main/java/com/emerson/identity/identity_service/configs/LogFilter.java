package com.emerson.identity.identity_service.configs;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Enumeration;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LogFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        LocalDateTime date = LocalDateTime.now();
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        System.err.println("------------------------------------------------------------------------");
        System.err.println("START LOGFILTER: "  + date + " - " + request.getLocalAddr() + ":" + request.getLocalPort() + request.getServletPath() + "\nRequest:");
        Enumeration<String> headers = request.getHeaderNames();
        while(headers.hasMoreElements()) {
            String headerName = (String)headers.nextElement();
            System.out.println("\tHeader: " + headerName + ":" + request.getHeader(headerName));
        }
        System.out.println("\n");
        Enumeration<String> parameters = request.getParameterNames();
        while(parameters.hasMoreElements()) {
            String parameterName = (String)parameters.nextElement();
            System.out.println("\tParameter: " + parameterName + ": " + request.getParameter(parameterName));
        }
        System.out.println("\n");
        Enumeration<String> attributes = request.getAttributeNames();
        while(attributes.hasMoreElements()) {
            String attributeName = (String)attributes.nextElement();
            System.out.println("\tAttribute: " + attributeName + ": " + request.getParameter(attributeName));
        }

        filterChain.doFilter(requestWrapper, responseWrapper);

        String requestBody = getStringValue(requestWrapper.getContentAsByteArray(),
                request.getCharacterEncoding());
        String responseBody = getStringValue(responseWrapper.getContentAsByteArray(),
                response.getCharacterEncoding());

        System.out.println("Request Body: " + requestBody + "\n");
        System.out.println("Response Body: " + responseBody + "\n");
        System.out.println("\n");
        Collection<String> responseHeaders = response.getHeaderNames();
        responseHeaders.forEach(x -> System.out.println("\tHeader: " + x + ": " + response.getHeader(x)));
        System.out.println("\n\n");


        /*
        getParts() method is used to retrieve a collection of Part objects that represent the parts
        of a "multipart/form-data" request. This is typically used when handling file uploads in
        a servlet.

            try{
                Collection<Part> parts = request.getParts();
                for(Part part: parts){
                    if(part.getContentType() != null){
                        InputStream inputStream = part.getInputStream();
                        String submittedFileName = part.getSubmittedFileName();
                        String contentType = part.getContentType();
                    }
            }
            }catch(Exception e){
                System.out.println(e.getMessage());
            }

         */


        System.err.println("END LOG FILTER");
        System.err.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");

        responseWrapper.copyBodyToResponse();
    }

    private String getStringValue(byte[] contentAsByteArray, String characterEncoding) {
        try {
            return new String(contentAsByteArray, 0, contentAsByteArray.length, characterEncoding);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }
}

/*
    HttpServletRequest (Java Servlet API):
    The HttpServletRequest interface provides methods to obtain information about the HTTP request. Here are some of the key properties and methods:

    Request Line:

    getMethod(): Returns the HTTP method (GET, POST, etc.).
    getRequestURI(): Returns the portion of the request URI that indicates the context of the request.
    getProtocol(): Returns the name and version of the protocol the request uses.
    Headers:

    getHeader(String name): Returns the value of the specified request header.
    getHeaders(String name): Returns all the values of the specified request header.
    getHeaderNames(): Returns an enumeration of all the header names sent in the request.
    Parameters:

    getParameter(String name): Returns the value of a request parameter.
    getParameterMap(): Returns a map containing all the parameters.
    getParameterNames(): Returns an enumeration of all the parameter names.
    Content:

    getInputStream(): Retrieves the body of the request as binary data.
    getReader(): Retrieves the body of the request as character data.
    Session and Cookies:

    getSession(): Returns the current session associated with the request.
    getCookies(): Returns an array of Cookie objects representing the cookies sent by the client.
    Other Information:

    getRemoteAddr(): Returns the IP address of the client or the last proxy that sent the request.
    getLocale(): Returns the preferred Locale that the client will accept content in.
 */