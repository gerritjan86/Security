using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebAppSecurity.Models
{
	public class RegisterModel
	{
		[Required, MinLength(2, ErrorMessage = "Must be at least 2 characters")]
		public string FirstName { get; set; }

		[Required, MinLength(2, ErrorMessage = "Must be at least 2 characters")]
		public string LastName { get; set; }

		[Required]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		public string Password { get; set; }

		[Required]
		[Display(Name = "Confirm Password")]
		public string ControlPassword { get; set; }

		[Required]
		public string CaptchaCode { get; set; }

	}
}
