package com.oyea.ebiz;

import static com.brightpoint.directconnect.core.util.LoggerUtil.args;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;

import org.apache.shiro.codec.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.brightpoint.directconnect.core.service.PropertyService;
import com.brightpoint.directconnect.core.util.ConfigurationException;
import com.brightpoint.directconnect.core.util.Constants;
import com.brightpoint.directconnect.core.util.CryptoService;
import com.brightpoint.directconnect.frontend.model.Entity;
import com.brightpoint.directconnect.frontend.model.EventType;
import com.brightpoint.directconnect.frontend.model.JsonResponse;
import com.brightpoint.directconnect.frontend.model.Request;
import com.brightpoint.directconnect.frontend.service.RequestProcessor;
import com.brightpoint.directconnect.frontend.service.velocity.VelocityService;

@Controller
@RequestMapping( value = "/json", produces = "application/json" )
public class PluginController {
	private static final Logger logger = LoggerFactory.getLogger( PluginController.class );

	@Autowired
	private CryptoService cryptoService;

	@Resource
	private PropertyService propertyService;

	@Resource
	private RequestProcessor requestProcessor;

	@Resource
	private VelocityService velocityService;

	@ExceptionHandler( Throwable.class )
	@ResponseBody
	public JsonResponse handleException( final Throwable throwable ) {
		String titleKey;
		String bodyKey;
		if( throwable instanceof ConfigurationException ) {
			logger.error( "A configuration error occured", throwable );
			titleKey = "client.error.configuration.exception.title";
			bodyKey = "client.error.configuration.exception.body";
		}
		else {
			logger.error( "An uncaught throwable hit " + PluginController.class.getName(), throwable );
			titleKey = "client.error.uncaught.throwable.title";
			bodyKey = "client.error.uncaught.throwable.body";
		}

		Map<String, Object> parameters = new HashMap<String, Object>();
		parameters.put( "title", propertyService.getLocalizedMessage( titleKey ) );
		parameters.put( "body", propertyService.getLocalizedMessage( bodyKey ) );
		String body = velocityService.processTemplateForWebClient( "scError.vm", parameters );

		JsonResponse errorResponse = new JsonResponse();
		errorResponse.setAction( Constants.ACTION_ERROR );
		errorResponse.setBody( body );
		return errorResponse;
	}

	@RequestMapping( value = "/action/{eventType}/{entity}/" )
	@ResponseBody
	public JsonResponse processRequest( @PathVariable final String eventType, @PathVariable final String entity ) {
		logger.debug( "/action/{}/{}/", args( eventType, entity ) );
		return processRequest( makeRequest( EventType.forName( eventType ), Entity.forName( entity ) ) );
	}

	@RequestMapping( value = "/action/{eventType}/{entity}/{value}/" )
	@ResponseBody
	public JsonResponse processRequest( @PathVariable final String eventType,
			@PathVariable final String entity,
			@PathVariable final String value ) {
		logger.debug( "/action/{}/{}/{}/", args( eventType, entity, value ) );
		return processRequest( makeRequest( EventType.forName( eventType ), Entity.forName( entity ), value ) );
	}

	@RequestMapping( value = "/action/{eventType}/{entity}/{value}/{parameters}/" )
	@ResponseBody
	public JsonResponse processRequest( @PathVariable final String eventType,
			@PathVariable final String entity,
			@PathVariable final String value,
			@PathVariable final String parameters ) {
		logger.debug( "/action/{}/{}/{}/{}/", args( eventType, entity, value, parameters ) );
		return processRequest( makeRequest( EventType.forName( eventType ), Entity.forName( entity ), value, parameters ) );
	}

	@RequestMapping( value = "/action/INIT/PRODUCT/DETAIL", method = RequestMethod.GET )
	@ResponseBody
	public JsonResponse initProductDetail( @RequestParam( "detail" ) final String detail,
			@RequestParam( "next" ) final String nextDetail,
			@RequestParam( "encrypted" ) final boolean isEncrypted,
			@RequestParam( "callback" ) final String callback ) {
		logger.debug( "/action/INIT/PRODUCT/DETAIL, next={}, encrypted={}, callback={}",
				args( nextDetail, isEncrypted, callback ) );
		Request request = new Request();
		request.setEntity( Entity.PRODUCT_DETAIL );
		request.setEventType( EventType.INIT );
		request.setValue( detail );
		detail.length();
		if( !isEncrypted ) {
			String parameters = detail + "|next=" + nextDetail;
			request.setParameters( parameters );
		}
		else {

			byte[] decodedDetail = cryptoService.rsaDecrypt( Base64.decode( detail ) );
			String decodedDetailString = new String( decodedDetail );
			String parameters = decodedDetailString + "|next=" + nextDetail;
			request.setParameters( parameters );
		}

		return processRequest( request );

	}

	private Request makeRequest( final Object... objects ) {
		Request retVal = new Request();
		for( Object object : objects ) {
			if( object == null ) {
				continue;
			}
			if( object instanceof EventType ) {
				retVal.setEventType( (EventType) object );
			}
			else if( object instanceof Entity ) {
				retVal.setEntity( (Entity) object );
			}
			else {
				String value = (String) object;
				if( value.contains( "=" ) ) {
					retVal.setParameters( value );
				}
				else {
					retVal.setValue( value );
				}
			}
		}
		return retVal;
	}

	private JsonResponse processRequest( final Request request ) {
		return requestProcessor.processRequest( request );
	}
}
