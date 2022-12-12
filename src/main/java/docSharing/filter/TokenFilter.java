package docSharing.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import docSharing.controller.DocController;
import docSharing.service.AuthService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;


public class TokenFilter implements Filter {

    private final AuthService authService;
    public TokenFilter(AuthService authService) {
        this.authService = authService;
    }

    private static final Logger logger = LogManager.getLogger(TokenFilter.class.getName());

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Called by the web container to indicate to a filter that it is being placed into service.
     * The servlet container calls the init method exactly once after instantiating the filter.
     * The init method must complete successfully before the filter is asked to do any filtering work.
     *
     * @param filterConfig The configuration information associated with the
     *                     filter instance being initialised
     * @throws ServletException
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {


        logger.info("Auth filter is working on the following request: " + servletRequest);
        //ServletRequest servletRequestWithParameter = (HttpServletRequest) servletRequest.;
        MutableHttpServletRequest req = new MutableHttpServletRequest((HttpServletRequest) servletRequest);
        HttpServletResponse res = (HttpServletResponse) servletResponse;
        String userId = req.getHeader("userId");
        String token = req.getHeader("token");
        if (token != null) {


            if (authService.isValidToken(Long.parseLong(userId), token)) {
//                req.setAttribute("userId", tokenCorrect.getData());
                filterChain.doFilter(req, res);

            } else returnBadResponse(res);
        } else

            returnBadResponse(res);

    }

    /**
     * Sends an error response to the client using status code 401, with message Unauthorized.
     *
     * @param res, HttpServletResponse object, contains response to a servlet request.
     * @throws IOException, if an input or output exception occurs.
     */
    private void returnBadResponse(HttpServletResponse res) throws IOException {
        res.sendError(401, "Unauthorized");
    }

    /**
     * indicate to a filter that it is being taken out of service.
     * This method is only called once all threads within the filter's doFilter method have exited or after a timeout period has passed.
     * After the web container calls this method, it will not call the doFilter method again on this instance of the filter.
     * This method gives the filter an opportunity to clean up any resources that are being held.
     */
    public void destroy() {
        Filter.super.destroy();
    }

}
