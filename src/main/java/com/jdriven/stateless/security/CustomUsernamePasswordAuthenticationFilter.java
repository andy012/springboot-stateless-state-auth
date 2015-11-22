package com.jdriven.stateless.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Created by andy on 11/21/15.
 */
public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        setDetails(request, (UsernamePasswordAuthenticationToken) authResult);

        HttpSession session = request.getSession(true);
        UserAuthentication userAuthentication=new UserAuthentication((User)(authResult.getPrincipal()));
        userAuthentication.setAuthenticated(authResult.isAuthenticated());
        session.setAttribute("SPRING_SECURITY_CONTEXT",userAuthentication);
        System.out.println(session.getAttribute("SPRING_SECURITY_CONTEXT"));
//        System.out.println(request.getSession().getAttributeNames());

//        while (request.getSession().getAttributeNames().hasMoreElements()){
//            String aName=request.getSession().getAttributeNames().nextElement();
//            System.out.println(aName+":"+request.getSession().getAttribute(aName).getClass());
//        }
        //SecurityContextHolder.getContext().setAuthentication(authResult);
        super.successfulAuthentication(request, response, chain, authResult);
       // System.out.println("######################" + SecurityContextHolder.getContext().getAuthentication());

    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        return super.attemptAuthentication(request, response);
    }

    @Override
    public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionStrategy) {
        super.setSessionAuthenticationStrategy(sessionStrategy);
    }


}
