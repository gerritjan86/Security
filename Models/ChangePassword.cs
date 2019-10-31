using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAppSecurity.Models
{
	public class ChangePassword
	{
		public int Id { get; set; }

		public string OldPassword { get; set; }

		public string NewPassword { get; set; }

		public string ConfirmNewPassword { get; set; }

		public string NewPasswordHash { get; set; }

	}
}
