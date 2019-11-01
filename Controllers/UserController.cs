using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;
using WebAppSecurity.Models.Captcha;

namespace WebAppSecurity.Controllers
{
    public class UserController : Controller
    {
		private readonly UserManager _userManager = new UserManager();
		private readonly ILogger _logger;

		public UserController(ILogger<UserController> logger) 
        {
			_logger = logger;
        }

		//GET User/Login
		[AllowAnonymous]
		[HttpGet]
		public IActionResult Login() => View();


		//POST User/Login
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		[HttpPost, ActionName("Login")]
		public async Task<IActionResult> LoginAsync([Bind("Email,Password")] LoginModel model)
		{
			if(model.Email.Equals(string.Empty) || model.Password.Equals(string.Empty) || model.Email.Equals("") || model.Password.Equals(""))
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(model);
			}

			User userDb = _userManager.GetUserByLoginModel(model);

			if (userDb == null || userDb.Id == 0)
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(model);
			}

			PasswordHasher<User> passwordHasher = new PasswordHasher<User>();
			PasswordVerificationResult verificationResult = passwordHasher.VerifyHashedPassword(userDb, userDb.PasswordHash, model.Password);
			
			if (verificationResult != PasswordVerificationResult.Success)
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(model);
			}

			if (verificationResult == PasswordVerificationResult.Success)
			{
				try
				{
					bool signIn = await _userManager.SignIn(HttpContext, userDb);
					if (signIn)
					{
						return RedirectToAction("LoggedIn", "Home");
					}
					else
					{
						ModelState.AddModelError(string.Empty, "Try again!");
						return View(model);
					}
				}
				catch (Exception)
				{
					ModelState.AddModelError(string.Empty, "Try again!");
					return View(model);
				}
			}

			ModelState.AddModelError(string.Empty, "Try again!");
			return View(model);
		}

		public async Task<IActionResult> Logout()
		{
			bool signOut = await _userManager.SignOut(HttpContext);
			if (signOut)
			{
				return RedirectToAction("LoggedOut", "Home");
			}
			else
			{
				return RedirectToAction("LoggedIn", "Home");
			}
		}


		// GET: User/Create
		[AllowAnonymous]
		public IActionResult Create()
        {
			return View();
        }


        // POST: User/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
        public IActionResult Create([Bind("FirstName,LastName,Email,Password,ControlPassword,CaptchaCode")] RegisterModel registerModel)
		{
            if (ModelState.IsValid)
            {
				if(registerModel.Password.Equals(registerModel.ControlPassword))
				{
					if (ValidatePassword(registerModel.Password))
					{
						if (Captcha.ValidateCaptchaCode(registerModel.CaptchaCode, HttpContext))
						{
							try
							{
								User user = new User
								{
									FirstName = registerModel.FirstName,
									LastName = registerModel.LastName,
									Email = registerModel.Email,
									Role = "User",
								};
								var hasher = new PasswordHasher<User>();
								user.PasswordHash = hasher.HashPassword(user, registerModel.Password);
								_userManager.AddUser(user);
								return RedirectToAction("UserRegistrationCompleted", "Home");
							}
							catch (Exception)
							{
								return View(registerModel);
							}
						}
						else
						{
							ModelState.AddModelError(string.Empty, "Wrong Captcha Code. Try again!");
							return View(registerModel);
						}
					}
					else
					{
						ModelState.AddModelError(string.Empty, "Password must be at least 8 charachters containing uppercase and lowercase letters and at least one number and one special character!");
						return View(registerModel);
					}
				}
				else
				{
					ModelState.AddModelError(string.Empty, "Password and Confirm Password do not match");
					return View(registerModel);
				}
            }
            return View(registerModel);
        }


		//Method to check password requirements
		private static bool ValidatePassword(string password)
		{
			const int MIN_LENGTH = 8;

			bool meetsLengthRequirements = password.Length >= MIN_LENGTH;
			bool hasUpperCaseLetter = false;
			bool hasLowerCaseLetter = false;
			bool hasDecimalDigit = false;
			bool hasSpecialCharacter = false;

			if (meetsLengthRequirements)
			{
				foreach (char c in password)
				{
					if (char.IsUpper(c)) hasUpperCaseLetter = true;
					else if (char.IsLower(c)) hasLowerCaseLetter = true;
					else if (char.IsDigit(c)) hasDecimalDigit = true;
					else if (Regex.IsMatch(c.ToString(), @"[!#$%&'()*+,-.:;<=>?@[\\\]{}^_`|~]")) hasSpecialCharacter = true;
				}
			}

			bool isValid = meetsLengthRequirements
						&& hasUpperCaseLetter
						&& hasLowerCaseLetter
						&& hasDecimalDigit
						&& hasSpecialCharacter
						;
			return isValid;
		}


		// GET: User/Details/5
		[Authorize(Roles = "User")]
		[HttpGet]
		public IActionResult Details(int? id)
		{
			if (id == null)
			{
				return NotFound();
			}

			IEnumerable<System.Security.Claims.Claim> userClaims = User.Claims;
			if (id != Convert.ToInt32(userClaims.ElementAt(0).Value))
			{
				return Forbid();
			}

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				return NotFound();
			}
			return View(user);
		}


		// GET: User/EditPassword/5
		[Authorize(Roles = "User")]
		[HttpGet]
		public IActionResult EditPassword(int? id)
		{
			if (id == null)
			{
				return NotFound();
			}

			IEnumerable<System.Security.Claims.Claim> userClaims = User.Claims;
			if (id != Convert.ToInt32(userClaims.ElementAt(0).Value))
			{
				return Forbid();
			}

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				return NotFound();
			}

			ChangePassword cp = new ChangePassword
			{
				Id = user.Id,
			};

			return View(cp);
		}

		// Post: User/EditPassword/5
		[Authorize(Roles = "User")]
		[ValidateAntiForgeryToken]
		[HttpPost]
		public IActionResult EditPassword(int id, [Bind("Id,OldPassword,NewPassword,ConfirmNewPassword")] ChangePassword changePassword)
		{
			IEnumerable<System.Security.Claims.Claim> userClaims = User.Claims;
			if (id != Convert.ToInt32(userClaims.ElementAt(0).Value))
			{
				return Forbid();
			}

			if (id != changePassword.Id)
			{
				return NotFound();
			}

			if (ValidatePassword(changePassword.NewPassword) == false)
			{
				ModelState.AddModelError(string.Empty, "Password must be at least 8 charachters containing uppercase and lowercase letters and at least one number and one special character!");
				return View(changePassword);
			}

			if (changePassword.NewPassword.Equals(changePassword.ConfirmNewPassword) == false)
			{
				ModelState.AddModelError(string.Empty, "Password and Confirm Password do not match");
				return View(changePassword);
			}

			if (ModelState.IsValid)
			{
				try
				{
					User user = new User();
					var hasher = new PasswordHasher<User>();
					user.PasswordHash = hasher.HashPassword(user, changePassword.NewPassword);
					changePassword.NewPasswordHash = user.PasswordHash;

					//update database with new the new password hash
					_userManager.UpdateUserPassword(changePassword);
				}
				catch (DbUpdateConcurrencyException)
				{
					if (!UserExists(changePassword.Id))
					{
						return NotFound();
					}
					else
					{
						throw;
					}
				}
				return RedirectToAction("ChangedPassword", "Home");
			}
			return View(changePassword);
		}


		// GET: User/Index
		// Returns view with all users. Page only accessible for Admin.
		[Authorize(Roles = "Admin")]
		public IActionResult Index()
		{
			return View(_userManager.Getusers());
		}

		// GET: User/Edit/5
		[Authorize(Roles = "Admin")]
		[HttpGet]
		public IActionResult Edit(int? id)
		{
			if (id == null)
			{
				return NotFound();
			}

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				return NotFound();
			}

			return View(user);
		}


		// POST: User/Edit/5
		// To protect from overposting attacks, please enable the specific properties you want to bind to, for 
		// more details see http://go.microsoft.com/fwlink/?LinkId=317598.
		[HttpPost]
        [ValidateAntiForgeryToken]
		[Authorize(Roles = "Admin")]
		public IActionResult Edit(int id, [Bind("Id,FirstName,LastName,Email,PasswordHash")] User user)
        {
            if (id != user.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
					_userManager.UpdateUser(user);

                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!UserExists(user.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(user);
        }


		// GET: User/Delete/5
		[Authorize(Roles = "Admin")]
		public IActionResult Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				return NotFound();
			}

			return View(user);
		}


        // POST: User/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
		[Authorize(Roles = "Admin")]
		public IActionResult DeleteConfirmed(int id)
        {
			User user = _userManager.GetUserById(id);
			_userManager.DeleteUser(user);
            return RedirectToAction(nameof(Index));
        }



        private bool UserExists(int id)
        {
			return _userManager.Getusers().Any(e => e.Id == id);
        }

	}
}
