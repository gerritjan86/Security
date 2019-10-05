using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace WebAppSecurity.Models
{
	public class User
	{
		[Key]
		public int Id { get; set; }

		[Required, MinLength(2, ErrorMessage = "Must be at least 2 characters")]
		public string FirstName { get; set; }

		[Required, MinLength(2, ErrorMessage = "Must be at least 2 characters")]
		public string LastName { get; set; }

		[Required]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		public string PasswordHash { get; set; }

		public string Role { get; set; }

		public string Token { get; set; }
	}
}
