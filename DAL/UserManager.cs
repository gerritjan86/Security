using Microsoft.AspNetCore.Http;
using System;
using System.Configuration;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Data.SqlClient;
using WebAppSecurity.Models;
using System.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace WebAppSecurity.DAL
{
	public class UserManager
	{

		public static string GetConnectionString()
		{
			return Startup.ConnectionString;
		}


		public async Task<bool> SignIn(HttpContext httpContext, User user, bool isPersistent = false)
		{
			ClaimsIdentity identity = new ClaimsIdentity(this.GetUserClaims(user), CookieAuthenticationDefaults.AuthenticationScheme);
			ClaimsPrincipal principal = new ClaimsPrincipal(identity);
			//await httpContext.SignOutAsync();
			await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
			return true;
		}


		public User GetUser(LoginModel loginModel)
		{
			using (var con = new SqlConnection(GetConnectionString()))
			{
				string queryString = "SELECT Id, Email, FirstName, LastName, PasswordHash, Role FROM users WHERE Email=@Email";

				con.Open();
				SqlCommand sqlCmd = new SqlCommand(queryString, con);
				sqlCmd.Parameters.AddWithValue("@Email", loginModel.Email);
				SqlDataReader rdr = sqlCmd.ExecuteReader(CommandBehavior.SingleRow);
				var userModel = new User();

				if (rdr.Read())
				{
					userModel.Id = Convert.ToInt32(rdr["Id"]);
					userModel.Email = rdr["Email"].ToString();
					userModel.FirstName = rdr["FirstName"].ToString();
					userModel.LastName = rdr["LastName"].ToString();
					userModel.PasswordHash = rdr["PasswordHash"].ToString();
					userModel.Role = rdr["Role"].ToString();
				}

				con.Close();

				return userModel;
			}
		}

		public async Task<bool> SignOut(HttpContext httpContext)
		{
			await httpContext.SignOutAsync();
			return true;
		}

		private IEnumerable<Claim> GetUserClaims(User user)
		{
			List<Claim> claims = new List<Claim>();

			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Name, user.FirstName + " " + user.LastName));
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
	}
}
