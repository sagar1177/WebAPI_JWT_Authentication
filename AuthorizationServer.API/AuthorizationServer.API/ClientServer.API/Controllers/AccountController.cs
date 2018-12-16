using AppDbContext.Data.Models;
using ClientServer.API.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace ClientServer.API.Controllers
{
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;
        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }


        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            ApplicationUser user = new ApplicationUser() { FirstName = model.FirstName, LastName = model.LastName, UserName = model.Email, Email = model.Email };
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            else
            {
                if (model.IsGuestUser)
                {
                    ApplicationDbContext db = new ApplicationDbContext();
                    Microsoft.AspNet.Identity.EntityFramework.IdentityRole role = db.Roles.FirstOrDefault(x => x.Name == "Guest");
                    var loginuser = db.Users.FirstOrDefault(x => x.Id == user.Id);
                    if (role == null)
                    {
                        role = new Microsoft.AspNet.Identity.EntityFramework.IdentityRole() { Id = Guid.NewGuid().ToString(), Name = "Guest" };
                        db.Roles.Add(role);

                    }

                    var userRole = new Microsoft.AspNet.Identity.EntityFramework.IdentityUserRole
                    {
                        UserId = user.Id,
                        RoleId = role.Id
                    };

                    loginuser.Roles.Add(userRole);
                    db.SaveChanges();

                }
            }
            return Ok();
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }
    }
}