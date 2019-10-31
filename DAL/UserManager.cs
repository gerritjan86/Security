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
using MySql.Data.MySqlClient;

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
			await httpContext.SignOutAsync();
			await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
			return true;
		}

		public async Task<bool> SignOut(HttpContext httpContext)
		{
			await httpContext.SignOutAsync();
			return true;
		}


		public User GetUserByLoginModel(LoginModel loginModel)
		{
			using (var conn = new MySqlConnection(GetConnectionString()))
			{
				try
				{
					string queryString = "SELECT * FROM users WHERE Email=@Email";

					conn.Open();
					MySqlCommand sqlCmd = new MySqlCommand(queryString, conn);
					sqlCmd.Parameters.AddWithValue("@Email", loginModel.Email);
					MySqlDataReader rdr = sqlCmd.ExecuteReader(CommandBehavior.SingleRow);
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

					conn.Close();
					return userModel;
				}
				finally
				{
					if(conn != null)
					{
						conn.Close();
					}
				}
			}
		}


		public User GetUserById(int userId)
		{
			using (var conn = new MySqlConnection(GetConnectionString()))
			{
				try
				{
					string queryString = "SELECT * FROM users WHERE Id=@Id";

					conn.Open();
					MySqlCommand sqlCmd = new MySqlCommand(queryString, conn);
					sqlCmd.Parameters.AddWithValue("@Id", userId);
					MySqlDataReader rdr = sqlCmd.ExecuteReader(CommandBehavior.SingleRow);
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

					conn.Close();
					return userModel;
				}
				finally
				{
					if (conn != null)
					{
						conn.Close();
					}
				}
			}
		}


		public void UpdateUserPassword(ChangePassword changePassword)
		{
			using (var conn = new MySqlConnection(GetConnectionString()))
			{
				try
				{
					string queryString = "UPDATE users SET PasswordHash=@PasswordHash WHERE Id=@Id";

					conn.Open();
					MySqlCommand sqlCmd = new MySqlCommand(queryString, conn);
					sqlCmd.Prepare();
					sqlCmd.Parameters.AddWithValue("@Id", changePassword.Id);
					sqlCmd.Parameters.AddWithValue("@PasswordHash", changePassword.NewPasswordHash);
					sqlCmd.ExecuteNonQuery();

					conn.Close();
				}
				finally
				{
					if (conn != null)
					{
						conn.Close();
					}
				}
			}
		}


		public void UpdateUser(User user)
		{
			using (var conn = new MySqlConnection(GetConnectionString()))
			{
				try
				{
					string queryString = "UPDATE users SET FirstName=@FirstName, LastName=@LastName, Email=@Email WHERE Id=@Id";

					conn.Open();
					MySqlCommand sqlCmd = new MySqlCommand(queryString, conn);
					sqlCmd.Prepare();
					sqlCmd.Parameters.AddWithValue("@Id", user.Id);
					sqlCmd.Parameters.AddWithValue("@FirstName", user.FirstName);
					sqlCmd.Parameters.AddWithValue("@LastName", user.LastName);
					sqlCmd.Parameters.AddWithValue("@Email", user.Email);
					sqlCmd.ExecuteNonQuery();

					conn.Close();
				}
				finally
				{
					if (conn != null)
					{
						conn.Close();
					}
				}
			}
		}


		public List<User> Getusers()
		{
			using (var conn = new MySqlConnection(GetConnectionString()))
			{
				try
				{
					List<User> userList = new List<User>();

					string queryString = "SELECT * FROM users";

					conn.Open();
					MySqlCommand sqlCmd = new MySqlCommand(queryString, conn);
					MySqlDataReader rdr = sqlCmd.ExecuteReader();
					
					while (rdr.Read())
					{
						var userModel = new User();
						userModel.Id = Convert.ToInt32(rdr["Id"]);
						userModel.Email = rdr["Email"].ToString();
						userModel.FirstName = rdr["FirstName"].ToString();
						userModel.LastName = rdr["LastName"].ToString();
						userModel.PasswordHash = rdr["PasswordHash"].ToString();
						userModel.Role = rdr["Role"].ToString();

						userList.Add(userModel);
					}

					conn.Close();
					return userList;
				}
				finally
				{
					if (conn != null)
					{
						conn.Close();
					}
				}
			}
		}


		public void AddUser(User user)
		{
			using (var conn = new MySqlConnection(GetConnectionString()))
			{
				try
				{
					string queryString = "INSERT INTO users (FirstName,LastName,Email,PasswordHash,Role) VALUES(@FirstName,@LastName,@Email,@PasswordHash,@Role)";

					conn.Open();
					MySqlCommand sqlCmd = new MySqlCommand(queryString, conn);
					sqlCmd.Prepare();
					sqlCmd.Parameters.AddWithValue("@FirstName", user.FirstName);
					sqlCmd.Parameters.AddWithValue("@LastName", user.LastName);
					sqlCmd.Parameters.AddWithValue("@Email", user.Email);
					sqlCmd.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);
					sqlCmd.Parameters.AddWithValue("@Role", user.Role);
					sqlCmd.ExecuteNonQuery();

					conn.Close();
				}
				finally
				{
					if (conn != null)
					{
						conn.Close();
					}
				}
				
			}
		}


		private IEnumerable<Claim> GetUserClaims(User user)
		{
			List<Claim> claims = new List<Claim>();

			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Name, user.FirstName + " " + user.LastName));
			claims.Add(new Claim(ClaimTypes.Email, user.Email));
			claims.Add(new Claim(ClaimTypes.Role, user.Role));
			return claims;
		}


	}
}
