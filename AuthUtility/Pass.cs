using AuthUtility;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;
using Google.Apis.Plus.v1;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AuthUtility
{
    public class PassData
    {
        // Google+
        public string access_token;
        public string refresh_token;
        public string code;
        //public int expires_in;
        //public string id_token;

        // Google+ (Computed)
        public DateTime issued;     // DateTime.UtcNow
        public DateTime expires;    // DateTime.UtcNow.AddSeconds(expires_in)
        public string googlePlusId; // Computed from id_token

        // Local
        public string userId;   // Hashed ID
        public string realId;   // eg. Plus-123456

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }

    /// <summary>
    /// A proof of authenticated User.
    /// </summary>
    public class Pass
    {
        // ----- Variables -----

        /// <summary>
        /// Pass data. Will be serialized to JSON and signed with SHA512.
        /// </summary>
        public PassData data = new PassData();

        /// <summary>
        /// SHA512 sign.
        /// </summary>
        //public string sign;

        /// <summary>
        /// Internal HttpContext for Google+ callbacks.
        /// </summary>
        HttpContext _httpContext;



        // ----- Properties -----

        /// <summary>
        /// Returns true if valid. If false, Pass should be discarded.
        /// </summary>
        /*public bool IsValid
        {
            get
            {
                var hash = AuthHelper.Hash(JsonConvert.SerializeObject(data));
                return sign == hash;
            }
        }*/



        // ----- Overrides -----

        /// <summary>
        /// Overrided ToString(). Displays states more nicely.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            //return string.Format("[Pass data:{0} sign:{1} IsValid:{2}]", data, sign, IsValid);
            return string.Format("[Pass data:{0}]", data);
        }



        // ----- Static Methods -----

        /// <summary>
        /// Generates Pass from results of OAuth.
        /// </summary>
        /// <param name="authObject">A response from Google+.</param>
        /// <returns></returns>
        public static Pass GenerateFromAuthObject(OAuthResponseObject authObject)
        {
            var googlePlusId = AuthHelper.GetGooglePlusId(authObject.id_token);
            var realId = "Plus-" + googlePlusId;
            var userId = AuthHelper.MD5Hash(realId);
            var data = new PassData()
            {
                access_token = authObject.access_token,
                refresh_token = authObject.refresh_token,
                code = authObject.code,
                //expires_in = authObject.expires_in,
                //id_token = authObject.id_token,

                issued = DateTime.UtcNow,
                expires = DateTime.UtcNow.AddSeconds(authObject.expires_in),
                googlePlusId = googlePlusId,

                userId = userId,
                realId = realId
            };
            var pass = new Pass() { data = data };
            //pass.SignData();
            return pass;
        }



        // ----- Methods -----

        /// <summary>
        /// Signs this Pass anyways. Even an evil data can be signed, be aware!
        /// </summary>
        /*public void SignData()
        {
            sign = AuthHelper.Hash(JsonConvert.SerializeObject(data));
        }*/

        /// <summary>
        /// Gets Google+ Service from PassData.
        /// Be noted, Google+ Service is thread unsafe.
        /// </summary>
        /// <param name="clientId">Google+ Client ID</param>
        /// <param name="clientSecret">Google+ Client Secret</param>
        /// <returns></returns>
        public PlusService GetPlusService(string clientId, string clientSecret)
        {
            // Register the authenticator and construct the Plus service
            // for performing API calls on behalf of the user.
            var description = Google.Apis.Authentication.OAuth2.GoogleAuthenticationServer.Description;
            var provider = new DotNetOpenAuth.OAuth2.WebServerClient(description);
            provider.ClientIdentifier = clientId;
            provider.ClientSecret = clientSecret;
            _httpContext = System.Web.HttpContext.Current;
            var authenticator =
                new Google.Apis.Authentication.OAuth2.OAuth2Authenticator<DotNetOpenAuth.OAuth2.WebServerClient>(
                    provider,
                    GetAuthorization)
                {
                    NoCaching = true
                };
            var ps = new Google.Apis.Plus.v1.PlusService(new Google.Apis.Services.BaseClientService.Initializer()
            {
                Authenticator = authenticator
            });
            return ps;
        }

        /// <summary>
        /// Returns DotNetOAuth AuthorizationState.
        /// </summary>
        /// <returns></returns>
        IAuthorizationState GetAuthState()
        {
            IAuthorizationState state = new AuthorizationState()
            {
                AccessToken = data.access_token,
                RefreshToken = data.refresh_token,
                AccessTokenIssueDateUtc = data.issued,
                AccessTokenExpirationUtc = data.expires
            };
            return state;
        }

        /// <summary>
        /// A callback for Google+ Service. Performs authentication using PassData.
        /// </summary>
        /// <param name="client"></param>
        /// <returns></returns>
        IAuthorizationState GetAuthorization(WebServerClient client)
        {
            var authState = GetAuthState();

            // If we don't yet have user, use the client to perform authorization.
            var reqinfo = new HttpRequestInfo(_httpContext.Request);
            client.ProcessUserAuthorization(reqinfo);

            // Check if we need to refresh the authorization state and refresh it if necessary.
            if (authState.AccessToken == null || DateTime.UtcNow > authState.AccessTokenExpirationUtc)
            {
                client.RefreshToken(authState);
            }

            // Update AuthState of Pass
            //SetAuthState(authState);

            return authState;
        }
    }
}