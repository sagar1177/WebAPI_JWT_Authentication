using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace ClientServer.API.Filters
{
    public class CustomAuthorize : AuthorizeAttribute
    {
        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
            if (actionContext.Request.Headers.Contains("Authorization"))
            {
                // get value from header
                string authenticationToken = Convert.ToString(
                  actionContext.Request.Headers.GetValues("Authorization").FirstOrDefault());

                if (actionContext.RequestContext.Principal.Identity.IsAuthenticated)
                {
                    ClaimsIdentity identity = actionContext.RequestContext.Principal.Identity as ClaimsIdentity;
                    string userRole = identity.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).FirstOrDefault();

                    if ((!string.IsNullOrEmpty(Roles) && string.IsNullOrEmpty(userRole)))
                    {
                        actionContext.Response = new HttpResponseMessage()
                        {
                            StatusCode = HttpStatusCode.Unauthorized,
                            Content = new JsonContent(
                               new
                               {
                                   Message = "You are not '" + Roles + "' user!. "
                               })
                        };
                    }

                    else if ((userRole != Roles && !string.IsNullOrEmpty(Roles) && !string.IsNullOrEmpty(userRole)))
                    {
                        actionContext.Response = new HttpResponseMessage()
                        {
                            StatusCode = HttpStatusCode.Unauthorized,
                            Content = new JsonContent(
                               new
                               {
                                   Message = "You are not '" + Roles + "' user!. "
                               })
                        };
                    }
                    return;
                }
                else
                {

                    //Check for Token Expired
                    var expiredStatus = JWTTokenDecode.CheckExpired(actionContext.Request.Headers.GetValues("Authorization").FirstOrDefault());
                    if (expiredStatus == 1)
                    {
                        actionContext.Response = new HttpResponseMessage()
                        {
                            StatusCode = HttpStatusCode.BadRequest,
                            Content = new JsonContent(
                              new
                              {
                                  Message = "Token has been expired for this request."
                              })
                        };

                        return;
                    }
                    else if (expiredStatus == -2147024809)
                    {
                        actionContext.Response = new HttpResponseMessage()
                        {
                            StatusCode = HttpStatusCode.BadRequest,
                            Content = new JsonContent(
                              new
                              {
                                  Message = "Invalid token passed."
                              })
                        };

                        return;
                    }


                    actionContext.Response = new HttpResponseMessage()
                    {
                        StatusCode = HttpStatusCode.Unauthorized,
                        Content = new JsonContent(
                                new
                                {
                                    Message = "Authorization has been denied for this request."
                                })
                    };

                    return;
                }
            }

            actionContext.Response = new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.Unauthorized,
                Content = new JsonContent(
                    new
                    {
                        Message = "Authorization has been denied for this request."
                    })
            };


        }
    }

    public class JsonContent : HttpContent
    {

        private readonly MemoryStream _Stream = new MemoryStream();
        public JsonContent(object value)
        {

            Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var jw = new JsonTextWriter(new StreamWriter(_Stream));
            jw.Formatting = Formatting.Indented;
            var serializer = new JsonSerializer();
            serializer.Serialize(jw, value);
            jw.Flush();
            _Stream.Position = 0;

        }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            return _Stream.CopyToAsync(stream);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _Stream.Length;
            return true;
        }
    }

    public static class JWTTokenDecode
    {
        public static int CheckExpired(string token)
        {
            try
            {
                var jwtEncodedString = token;
                if (token.Contains("bearer"))
                    jwtEncodedString = jwtEncodedString.Substring(7); // trim 'Bearer ' from the start since its just a prefix for the token string
                var securitytoken = new JwtSecurityToken(jwtEncodedString);
                var exp = securitytoken.Claims.First(c => c.Type == "exp").Value;

                DateTime dtExpired = new DateTime(1970, 1, 1, 0, 0, 0, 0);

                // Add the timestamp (number of seconds since the Epoch) to be converted
                dtExpired = dtExpired.AddSeconds(Convert.ToInt64(exp)).ToUniversalTime();
                DateTime dtUTCNow = DateTime.UtcNow;

                return dtUTCNow > dtExpired ? 1 : 0;
            }
            catch (Exception ex)
            {
                return ex.HResult;
            }
        }
    }

}