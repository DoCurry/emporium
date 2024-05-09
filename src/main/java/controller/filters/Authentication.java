package controller.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import util.StringUtils;

@WebFilter("/*")
public class Authentication implements Filter {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
	        throws IOException, ServletException {

	    // Cast request and response objects to HttpServletRequest and HttpServletResponse for type safety
	    HttpServletRequest req = (HttpServletRequest) request;
	    HttpServletResponse res = (HttpServletResponse) response;

	    // Get the requested URI
	    String uri = req.getRequestURI();
	    System.out.println("filtering uri = "+uri);

	    // Allow access to static resources (CSS) and the index page without checking login
	    if (uri.endsWith(".css") || uri.contains("/resource/") || uri.contains("/script/") || uri.contains("error.jsp") || uri.endsWith("/login")) {
	        chain.doFilter(request, response);
	        return;
	    }

	    // Separate flags for login, login/logout servlets, and register page/servlet for better readability
	    boolean isLogin = uri.endsWith(StringUtils.PAGE_URL_LOGIN);
	    boolean isLoginServlet = uri.endsWith(StringUtils.SERVLET_URL_LOGIN);

	    boolean isRegisterPage = uri.endsWith(StringUtils.PAGE_URL_REGISTER);
	    boolean isRegisterServlet = uri.endsWith(StringUtils.SERVLET_URL_REGISTER);
	    
	    boolean isLogoutServlet = uri.endsWith(StringUtils.SERVLET_URL_LOGOUT);

	    // Check if a session exists and if the username attribute is set to determine login status
	    HttpSession session = req.getSession(false); // Don't create a new session if one doesn't exist
	    boolean isLoggedIn = session != null && session.getAttribute(StringUtils.USERNAME) != null;

	    System.out.println("logged in? ="+isLoggedIn);
	    
	    // Redirect to login if user is not logged in and trying to access a protected resource
	    if (!isLoggedIn && !(isLogin || isLoginServlet || isRegisterPage || isRegisterServlet)) {
	        res.sendRedirect(req.getContextPath() + StringUtils.SERVLET_URL_LOGIN);
	    } else if (isLoggedIn && !(isLogoutServlet)) { 
	    	String role = session.getAttribute(StringUtils.ROLE).toString();
	    	
	    	System.out.println("role="+role);
	    	
	    	if (role.equals("admin") && (uri.contains("pages/admin/")||(uri.contains("/Admin")))) {// Redirect logged-in users to the index page if trying to access login page again
	    		chain.doFilter(req, res);
	    	} else if (role.equals("user") && (uri.contains("pages/user/")||(uri.contains("/User")))){
	    		chain.doFilter(request, response);
	    	}
	    	else {
	    		res.sendRedirect(req.getContextPath()+"/pages/error.jsp");
	    	}
	    } else {
	        chain.doFilter(request, response);
	    }
	    }


	@Override
	public void destroy() {
	}
}