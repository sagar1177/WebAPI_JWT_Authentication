using ClientServer.API.Filters;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Http;

namespace ClientServer.API.Controllers
{

    [RoutePrefix("api/protected")]
    public class ProtectedController : ApiController
    {
        [CustomAuthorize]
        [Route("GetClaims")]
        public IEnumerable<object> GetClaims()
        {
            var identity = User.Identity as ClaimsIdentity;

            var loggedIDUserId = User.Identity.GetUserId();

            return identity.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            });
        }

        
        [CustomAuthorize]
        [Route("GetUserID")]
        public IEnumerable<object> GetUserID()
        {
            var loggedIDUserId = User.Identity.GetUserId();
            List<object> result = new List<object>();
            result.Add(new { UserID = loggedIDUserId });
            return result;
        }
        
        [CustomAuthorize(Roles = "Guest")]
        [Route("GetGuestMessage")]
        public IEnumerable<object> GetGuestMessage()
        {
            List<object> result = new List<object>();
            result.Add(new { Message = "Welcome authenticated guest user" });
            return result;
        }
    }
}