using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebAppSecurity.DAL;

namespace WebAppSecurity.Models
{
	public static class SeedData
	{
		public static void Initialize(SecurityContext securityContext)
		{
			securityContext.Database.EnsureCreated();

			UserManager userManager = new UserManager();
			var userList = userManager.Getusers();
			User userAdmin = userList.FirstOrDefault(u => u.FirstName.Equals("Arie") && u.LastName.Equals("Bombari") && u.Email.Equals("arie@min.nl"));

			//first check if Arie Bombari already exists, if not then we will add Arie Bombarie to users table
			if (userAdmin == null)
			{
				User user = new User
				{
					FirstName = "Arie",
					LastName = "Bombari",
					Email = "arie@min.nl",
					Role = "Admin",
				};
				var hasher = new PasswordHasher<User>();
				user.PasswordHash = hasher.HashPassword(user, "DatLijktMeOok1!");
				userManager.AddUser(user);
			}
		}
	}
}
