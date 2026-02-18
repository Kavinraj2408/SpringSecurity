package com.kavindev.SpringSecurity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.naming.AuthenticationException;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ControllerAdvice {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> authenticationExceptionHandler(){
        Map<String,Object> map = new HashMap<>();
        map.put("message","Bad creadentials");
        map.put("status",false);
        return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
    }
}
