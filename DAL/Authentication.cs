using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using WebAppSecurity.Models;

namespace WebAppSecurity.DAL
{
	public class Authentication
	{
		private readonly SecurityContext _context;

		//constructor without params
		public Authentication()
		{

		}

		//constructor with one parameter
		public Authentication(SecurityContext context)
		{
			_context = context;
		}


		public async Task<bool> SignIn(HttpContext httpContext, User user, bool isPersistent = false)
		{
			ClaimsIdentity identity = new ClaimsIdentity(this.GetUserClaims(user), CookieAuthenticationDefaults.AuthenticationScheme);
			ClaimsPrincipal principal = new ClaimsPrincipal(identity);
			await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
			return true;
		}


		private IEnumerable<Claim> GetUserClaims(User user)
		{
			List<Claim> claims = new List<Claim>();

			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Name, user.FirstName + user.LastName));
			claims.Add(new Claim(ClaimTypes.Email, user.Email));
			claims.AddRange(this.GetUserRoleClaims(user));
			return claims;
		}


		private IEnumerable<Claim> GetUserRoleClaims(User user)
		{
			List<Claim> claims = new List<Claim>();

			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Role, user.Role));
			return claims;
		}


		public async void SignOut(HttpContext httpContext)
		{
			await httpContext.SignOutAsync();
		}




	}
}
