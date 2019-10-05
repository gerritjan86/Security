using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;

namespace WebAppSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
		private readonly SecurityContext _context;

		public AccountController(SecurityContext context)
		{
			_context = context;
		}


		// POST api/Account
		[AllowAnonymous]
		[HttpPost]
		public IActionResult Validate([FromBody] Account account)
		{
			User user = _context.Users.FirstOrDefault(u => u.Email.Equals(account.Email));

			if (user == null)
			{
				return BadRequest();
			}

			if(account.Email.Equals(string.Empty) || account.Password.Equals(string.Empty))
			{
				return BadRequest();
			}

			if (!account.Email.Equals(string.Empty) && !account.Password.Equals(string.Empty))
			{
				PasswordHasher<User> passwordHasher = new PasswordHasher<User>();
				PasswordVerificationResult verificationResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, account.Password);

				if(verificationResult == PasswordVerificationResult.Success)
				{
					return Ok();
				}

				if(verificationResult == PasswordVerificationResult.Failed)
				{
					return BadRequest();
				}
			}

			return BadRequest();
			//return Ok(new { token = GenerateJsonWebToken(user) });
		}


	}
}