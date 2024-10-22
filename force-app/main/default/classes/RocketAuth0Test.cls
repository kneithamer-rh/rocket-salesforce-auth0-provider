/**
 * @description Unit test for the RocketAuth0 class
 * @author      Bryan Crist
 */
@isTest
private class RocketAuth0Test {
    /**
     * @description Confirms Custom Metadata Type is set.
     */
    @isTest
    static void getCustomMetadataType_CmdtSet() {
        RocketAuth0 instance = new RocketAuth0();
        Assert.areEqual(RocketAuth0.CUSTOM_METADATA_TYPE, instance.getCustomMetadataType(), 'CMDT not set correctly');
    }

    /**
     * @description Ensures initiating URL has proper format
     */
    @isTest
    static void initiate_CallbackUrlReturned() {
        RocketAuth0 instance = new RocketAuth0();
        Map<String, String> config = new Map<String, String>();
        config.put('Auth_Provider__c', 'foo');
        final String state = 'randomState';

        Test.startTest();
        PageReference ref = instance.initiate(config, state);
        Test.stopTest();

        Assert.areEqual(
            URL.getOrgDomainURL().toExternalForm() + '/services/authcallback/foo?state=randomState',
            ref.getUrl(),
            'Callback URL not generated as expected'
        );
    }

    /**
     * @description Ensures auth request is sent successfully and retrieves proper response.
     */
    @isTest
    static void handleCallback_Success() {
        Map<String, String> config = new Map<String, String>();
        config.put('Audience__c', 'audienceId');
        config.put('Scopes__c', 'scope1 scope2');
        config.put('Named_Credential__c', 'Rocket_Auth0_Beta');

        final String mockResponse = '{"access_token": "dummy_access_token"}';

        final TokenEndpointHttpCalloutMockImpl httpMock = new TokenEndpointHttpCalloutMockImpl(mockResponse);
        Test.setMock(HttpCalloutMock.class, httpMock);

        RocketAuth0 instance = new RocketAuth0();
        final Map<String, String> queryArgs = new Map<String, String>();
        queryArgs.put('state', 'randomState');
        Auth.AuthProviderCallbackState callbackState = new Auth.AuthProviderCallbackState(
            new Map<String, String>(),
            '',
            queryArgs
        );

        Test.startTest();
        Auth.AuthProviderTokenResponse response = instance.handleCallback(config, callbackState);
        Test.stopTest();

        httpMock.assertUrl('callout:Rocket_Auth0_Beta');
        httpMock.assertContentType('application/json');
        httpMock.assertMethod('POST');
        Assert.isTrue(httpMock.callBody.contains('client_id'));
        Assert.isTrue(httpMock.callBody.contains('{!$Credential.Username}'));
        Assert.isTrue(httpMock.callBody.contains('client_secret'));
        Assert.isTrue(httpMock.callBody.contains('{!$Credential.Password}'));
        Assert.isTrue(httpMock.callBody.contains('audience'));
        Assert.isTrue(httpMock.callBody.contains('audienceId'));
        Assert.isTrue(httpMock.callBody.contains('grant_type'));
        Assert.isTrue(httpMock.callBody.contains('client_credentials'));
        Assert.areEqual(RocketAuth0.AUTH_PROVIDER_NAME, response.provider, 'Incorrect auth provider');
        Assert.areEqual('dummy_access_token', response.oauthToken, 'Incorrect auth token returned');
        Assert.areEqual('randomState', response.state, 'Incorrect callback state');
    }

    /**
     * @description Ensures proper error handling for failed authentication requests.
     */
    @isTest
    static void handleCallback_Error() {
        Map<String, String> config = new Map<String, String>();
        config.put('Audience__c', 'audienceId');
        config.put('Scopes__c', 'scope1,scope2');
        config.put('Named_Credential__c', 'Rocket_Auth0_Beta');

        final String mockResponse = '{"errorCode": "SOME_ERROR", "errorMessage": "Some description"}';
        final TokenEndpointHttpCalloutMockImpl httpMock = new TokenEndpointHttpCalloutMockImpl(mockResponse);
        httpMock.setResponseStatus(500);
        Test.setMock(HttpCalloutMock.class, httpMock);

        final Map<String, String> queryArgs = new Map<String, String>();
        Auth.AuthProviderCallbackState callbackState = new Auth.AuthProviderCallbackState(
            new Map<String, String>(),
            '',
            queryArgs
        );

        try {
            RocketAuth0 instance = new RocketAuth0();
            Auth.AuthProviderTokenResponse response = instance.handleCallback(config, callbackState);
            Assert.fail('Expected method to throw exception');
        } catch (RocketAuth0.RocketAuth0Exception e) {
            // assert
            httpMock.assertUrl('callout:Rocket_Auth0_Beta');
            httpMock.assertContentType('application/json');
            httpMock.assertMethod('POST');
            String expectedMessage = 'Rocket Auth0 token request failed. Response: 500 : ' + mockResponse;
            Assert.areEqual(expectedMessage, e.getMessage(), 'Exception has incorrect message');
        }
    }

    /**
     * @description Ensures required but unused getUserInfo method is functioning.
     */
    @isTest
    static void getUserInfo_DefaultUserInfo() {
        RocketAuth0 instance = new RocketAuth0();
        Auth.UserData r = instance.getUserInfo(null, null);
        Assert.areEqual(RocketAuth0.USERNAME, r.username, 'Incorrect username in user info');
        Assert.areEqual(RocketAuth0.AUTH_PROVIDER_NAME, r.provider, 'Incorrect provider in user info');
    }

    /**
     * @description Ensures auth refresh is handled successfully and retrieves updated access token.
     */
    @isTest
    static void refresh_Success() {
        Map<String, String> config = new Map<String, String>();
        config.put('Audience__c', 'audienceId');
        config.put('Scopes__c', 'scope1,scope2');
        config.put('Named_Credential__c', 'Rocket_Auth0_Beta');

        final String mockResponse = '{"access_token": "dummy_access_token"}';

        final TokenEndpointHttpCalloutMockImpl httpMock = new TokenEndpointHttpCalloutMockImpl(mockResponse);
        Test.setMock(HttpCalloutMock.class, httpMock);

        Test.startTest();
        RocketAuth0 instance = new RocketAuth0();
        Auth.OAuthRefreshResult response = instance.refresh(config, null);
        Test.stopTest();

        httpMock.assertUrl('callout:Rocket_Auth0_Beta');
        httpMock.assertContentType('application/json');
        httpMock.assertMethod('POST');
        Assert.areEqual('dummy_access_token', response.accessToken, 'Incorrect access token returned');
    }

    /**
     * @description Generates a mock callout with methods for asserting different aspects of the callout.
     */
    private class TokenEndpointHttpCalloutMockImpl implements HttpCalloutMock {
        private String callUrl;
        private String callMethod;
        private String callBody;
        private Map<String, String> callHeaders = new Map<String, String>();
        private String responseBody;
        private String responseContentType = 'application/json';
        private Integer responseStatus = 200;

        public TokenEndpointHttpCalloutMockImpl(String response) {
            this.responseBody = response;
        }

        public TokenEndpointHttpCalloutMockImpl(String response, String contentType) {
            this(response);
            this.responseContentType = contentType;
        }

        public TokenEndpointHttpCalloutMockImpl setResponseStatus(Integer status) {
            this.responseStatus = status;
            return this;
        }

        public void assertMethod(String method) {
            if (String.isEmpty(this.callMethod)) {
                Assert.fail('Method never set');
            }
            Assert.areEqual(method, this.callMethod);
        }

        public void assertUrl(String url) {
            if (String.isEmpty(this.callUrl)) {
                Assert.fail('URL never called');
            }
            Assert.areEqual(url, this.callUrl);
        }

        public void assertBody(String body) {
            if (String.isEmpty(this.callBody)) {
                Assert.fail('URL never called');
            }
            Assert.areEqual(body, this.callBody);
        }

        public void assertContentType(String value) {
            this.assertHeader('Content-Type', value);
        }

        public void assertHeader(String key, String value) {
            if (this.callHeaders.size() == 0) {
                Assert.fail('No headers');
            }
            if (String.isEmpty(key)) {
                Assert.fail('Must supply header name');
            }
            String v = this.callHeaders.get(key.toLowerCase());
            if (String.isEmpty(v)) {
                Assert.fail('Header not set');
            }
            Assert.areEqual(value, v);
        }

        public HTTPResponse respond(HTTPRequest req) {
            this.callUrl = req.getEndpoint();
            this.callMethod = req.getMethod();
            this.callBody = req.getBody();
            this.callHeaders.put('content-type', req.getHeader('Content-Type'));
            this.callHeaders.put('accept', req.getHeader('Accept'));

            // Create a fake response
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', this.responseContentType);
            res.setBody(this.responseBody);
            res.setStatusCode(this.responseStatus);
            return res;
        }
    }
}