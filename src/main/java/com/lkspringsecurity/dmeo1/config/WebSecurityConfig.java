package com.lkspringsecurity.dmeo1.config;

import com.lkspringsecurity.dmeo1.authcation.MyAuthenticationProcessingFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //拦截器需要在此注册
        http.addFilterBefore(new MyAuthenticationProcessingFilter(), AbstractPreAuthenticatedProcessingFilter.class);
    }
}
