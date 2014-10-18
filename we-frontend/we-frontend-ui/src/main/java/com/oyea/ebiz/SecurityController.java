package com.oyea.ebiz;

import javax.annotation.Resource;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.brightpoint.directconnect.core.model.integration.api.Response;
import com.brightpoint.directconnect.core.security.SecurityService;
import com.brightpoint.directconnect.core.util.Constants;
import com.brightpoint.directconnect.core.util.CryptoService;
import com.brightpoint.directconnect.core.util.SessionIdentifiers;
import com.brightpoint.directconnect.frontend.model.JsonResponse;
import com.brightpoint.directconnect.frontend.service.OrderHolder;

@Controller
@RequestMapping(value = "/json/authentication", produces = "application/json")
public class SecurityController {
    @Resource
    private CryptoService cryptoService;
    @Resource
    private OrderHolder orderHolder;
    @Resource
    private SecurityService securityService;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    @ResponseBody
    public JsonResponse getLoginResponse(
                    @RequestParam("code") final String rsaencoded,
                    @RequestParam("uoids") final String orderReference,
                    @RequestParam("callback") final String callback) {
        JsonResponse retVal = new JsonResponse();
 
        if (!securityService.isCurrentUserAuthenticated()) {
            // First-time authentication needed
            // Request does not contain cookie SCSession ,therefore no corresponding Server Session is found
            // Upon successful authentication
            // Initialize a new configuration or use existing if any unless it is completed, 
            // then load it to a new Server Session

            String encoded = rsaencoded.replace(" ", "+");
            byte[] authenticationToken = cryptoService.rsaDecrypt(Base64.decode(encoded));
            
            if (authenticationToken != null && securityService.login(new String(authenticationToken).toCharArray())) {
                // First-time authentication is successful
                return initOrder(orderReference);
             
            } else {
                String reason = "Invalid credentials provided. Check log messages (DEBUG level)";
                retVal.setAction( Constants.ACTION_ERROR );
                retVal.setBody("Authentication failed <br>" + reason);
                return retVal;
            }
        } else { 
            // Authentication not needed
            // Loading SC form requested once again on already authenticated session
            // Request must have SCSession cookie included and corresponding Server Session must be found
            // with existing orders in it
        	return initOrder(orderReference);
        }
    }
    
    @RequestMapping(value = "/timeout", method = RequestMethod.GET)
    @ResponseBody
    public JsonResponse getTimeoutResponse() {
    	Session session = securityService.getSession();
    	session.setAttribute( SessionIdentifiers.SESSION_TIMEOUT, Boolean.TRUE );
    	
        JsonResponse response = new JsonResponse();
        response.setAction( "reset" );
        return response;
    }
    
    private JsonResponse initOrder(final String orderReference) {
    	JsonResponse retVal = new JsonResponse();
    	
    	 Response<Boolean> response = orderHolder.initOrder(orderReference);
         if (response.getResponse()) {
             //retVal.setAction("initOffer");
             
             // enable using multiple HTTP GET instead of IFrame form submit
             // In order to rollback to IFrame solution, set action to initOffer as above. 
             retVal.setAction("initProductDetail");
             retVal.setActionParam("first"); 
         } else {
             retVal.setAction( Constants.ACTION_ERROR );
             retVal.setBody(response.getMessage());
         }
         return retVal;
    }
   
}
