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
				_logger.LogWarning("Login failed because of empty emailaddress and/or empty password");
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(model);
			}

			User userDb = _userManager.GetUserByLoginModel(model);

			if (userDb == null || userDb.Id == 0)
			{
				_logger.LogWarning("Login failed. No user found for emailaddress: {email}", model.Email);
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(model);
			}

			PasswordHasher<User> passwordHasher = new PasswordHasher<User>();
			PasswordVerificationResult verificationResult = passwordHasher.VerifyHashedPassword(userDb, userDb.PasswordHash, model.Password);
			
			if (verificationResult != PasswordVerificationResult.Success)
			{
				_logger.LogWarning("Login failed because of wrong password. User id: {id}", userDb.Id);
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
						_logger.LogInformation("Login with user id: {id}", userDb.Id.ToString());
						return RedirectToAction("LoggedIn", "Home");
					}
					else
					{
						ModelState.AddModelError(string.Empty, "Try again!");
						return View(model);
					}
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, "Login led to exception for user with id: {id}", userDb.Id);
					ModelState.AddModelError(string.Empty, "Try again!");
					return View(model);
				}
			}

			ModelState.AddModelError(string.Empty, "Try again!");
			return View(model);
		}

		public async Task<IActionResult> Logout()
		{
			IEnumerable<System.Security.Claims.Claim> userClaims = User.Claims;
			bool signOut = await _userManager.SignOut(HttpContext);
			if (signOut)
			{
				_logger.LogInformation("Logout for user id: {id}", userClaims.ElementAt(0).Value);
				return RedirectToAction("LoggedOut", "Home");
			}
			else
			{
				_logger.LogWarning("Logout failde for user id: {id}", userClaims.ElementAt(0).Value);
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
			if (ModelState.IsValid == false)
			{
				_logger.LogWarning("Register user failed because of invalid ModelState");
				return View(registerModel);
			}

			if (registerModel.Password.Equals(registerModel.ControlPassword) == false)
			{
				_logger.LogInformation("Register user failed because of mismatch between password and confirm password");
				ModelState.AddModelError(string.Empty, "Password and Confirm Password do not match");
				return View(registerModel);
			}

			if (ValidatePassword(registerModel.Password) == false)
			{
				_logger.LogInformation("Register user failed because of password requirements that were not met");
				ModelState.AddModelError(string.Empty, "Password must be at least 8 charachters containing uppercase and lowercase letters and at least one number and one special character!");
				return View(registerModel);
			}


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
					_logger.LogInformation("Registered new user with emailaddress: {email}", registerModel.Email);
					return RedirectToAction("UserRegistrationCompleted", "Home");
				}
				catch (Exception)
				{
					return View(registerModel);
				}
			}
			else
			{
				_logger.LogInformation("Register user failed because of wrong captcha code");
				ModelState.AddModelError(string.Empty, "Wrong Captcha Code. Try again!");
				return View(registerModel);
			}		
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
				_logger.LogInformation("User Details GET. User with id {a} tried to acces details of user with id {b}", userClaims.ElementAt(0).Value, id.ToString());
				return Forbid();
			}

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				_logger.LogInformation("User Details GET. GetUserById with id {a} led to a null-user or a user with id equal to 0.", id.ToString());
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
				_logger.LogInformation("Edit Password GET. User with id {a} tried to change password for user with id {b}", userClaims.ElementAt(0).Value, id.ToString());
				return Forbid();
			}

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				_logger.LogInformation("Edit Password GET. GetUserById with id {a} led to a null-user or a user with id equal to 0.", id.ToString());
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
				_logger.LogInformation("Edit Password POST. User with id {a} tried to change password for user with id {b}", userClaims.ElementAt(0).Value, id.ToString());
				return Forbid();
			}

			if (id != changePassword.Id)
			{
				_logger.LogInformation("Edit Password POST. Route value for id ({a}) differs from changePassword.Id ({b})", id.ToString(), changePassword.Id.ToString());
				return NotFound();
			}

			if (ValidatePassword(changePassword.NewPassword) == false)
			{
				_logger.LogInformation("Edit Password POST. New password does not meet password requirements. User id is {a} ", changePassword.Id.ToString());
				ModelState.AddModelError(string.Empty, "Password must be at least 8 charachters containing uppercase and lowercase letters and at least one number and one special character!");
				return View(changePassword);
			}

			if (changePassword.NewPassword.Equals(changePassword.ConfirmNewPassword) == false)
			{
				_logger.LogInformation("Edit Password POST. New password does not match with confirm new password. User id is {a} ", changePassword.Id.ToString());
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
					_logger.LogInformation("Edit password POST. User (id: {a}) changed password.", changePassword.Id.ToString());
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
				_logger.LogInformation("User Edit GET. Id is null does not work!");
				return NotFound();
			}

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				_logger.LogInformation("User Edit GET. GetUserById wiht id {a} led to a null-user or user with id 0.", id.ToString());
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
				_logger.LogInformation("User Edit POST. Route value id ({a}) different from user id ({b})", id.ToString(), user.Id.ToString());
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
					_userManager.UpdateUser(user);
					_logger.LogInformation("User Edit POST. Updated FirstName, LastName, Email for user with id: {}", user.Id.ToString());
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!UserExists(user.Id))
                    {
						_logger.LogInformation("User Edit POST. Something went wrong with updating the user");
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
				_logger.LogInformation("User Delete GET. Id is null does not work!");
				return NotFound();
            }

			User user = _userManager.GetUserById(id ?? 0);

			if (user == null || user.Id == 0)
			{
				_logger.LogInformation("User Edit GET. GetUserById wiht id {a} led to a null-user or user with id 0.", id.ToString());
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
			_logger.LogInformation("Deleted user with id: {id}", id.ToString());
            return RedirectToAction(nameof(Index));
        }



        private bool UserExists(int id)
        {
			return _userManager.Getusers().Any(e => e.Id == id);
        }

	}
}
