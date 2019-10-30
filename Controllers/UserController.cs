﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;
using WebAppSecurity.Models.Captcha;

namespace WebAppSecurity.Controllers
{
    public class UserController : Controller
    {
        private readonly SecurityContext _context;
		private readonly Authentication _auth = new Authentication();
		private readonly UserManager _userManager = new UserManager(); //DAL

        public UserController(SecurityContext context)
        {
            _context = context;
        }

		//GET User/Login
		//Login view where user can fill in his emailaddress and password
		[AllowAnonymous]
		[HttpGet]
		public IActionResult Login() => View();


		//POST User/Login
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		[HttpPost, ActionName("Login")]
		public async Task<IActionResult> LoginAsync([Bind("Email,Password")] LoginModel loginModel)
		{
			//User userDb = _context.Users.FirstOrDefault(u => u.Email.Equals(loginModel.Email));
			User userDb = _userManager.GetUser(loginModel);

			if (userDb == null)
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(loginModel);
			}

			if (loginModel.Email.Equals(string.Empty) || loginModel.Password.Equals(string.Empty))
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(loginModel);
			}

			if (!loginModel.Email.Equals(string.Empty) && !loginModel.Password.Equals(string.Empty))
			{
				PasswordHasher<User> passwordHasher = new PasswordHasher<User>();
				string hash = passwordHasher.HashPassword(userDb, loginModel.Password);
				PasswordVerificationResult verificationResult = passwordHasher.VerifyHashedPassword(userDb, userDb.PasswordHash, loginModel.Password);
				//verificationResult == PasswordVerificationResult.Success
				if (verificationResult == PasswordVerificationResult.Success)
				{
					try
					{
						bool signIn = await _auth.SignIn(HttpContext, userDb);
						if (signIn)
						{
							return RedirectToAction("LoggedIn", "Home");
						}
						else
						{
							ModelState.AddModelError(string.Empty, "Try again!");
							return View(loginModel);
						}
					}
					catch (Exception)
					{
						ModelState.AddModelError(string.Empty, "Try again!");
						return View(loginModel);
					}
				}
				else
				{
					ModelState.AddModelError(string.Empty, "Try again!");
					return View(loginModel);
				}
			}

			ModelState.AddModelError(string.Empty, "Try again!");
			return View(loginModel);
		}

		public async Task<IActionResult> Logout()
		{
			bool signOut = await _auth.SignOut(HttpContext);
			if (signOut)
			{
				return RedirectToAction("LoggedOut", "Home");
			}
			else
			{
				ModelState.AddModelError(string.Empty, "Strange...");
				return RedirectToAction("LoggedIn", "Home");
			}
		}

		[Authorize(Roles = "Admin")]
		[HttpGet]
		public IActionResult GetAll()
		{
			var users = this.GetAllUsers(true);
			return View(users);
		}


		[Authorize(Roles = "Admin, User")]
		[HttpGet]
		public IActionResult ShowUsers()
		{
			var users = this.GetAllUsers(false);
			return View(users);
		}


		public List<User> GetAllUsers(bool admin)
		{
			if (admin)
			{
				var userList = from user in _context.Users
							   select new User { FirstName = user.FirstName, LastName = user.LastName, Email = user.Email, Role = user.Role };
				var users = userList.ToList<User>();
				return users;
			}
			else
			{
				var userList = from user in _context.Users
							   select new User { FirstName = user.FirstName, LastName = user.LastName };
				var users = userList.ToList<User>();
				return users;
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
        public async Task<IActionResult> Create([Bind("Id,FirstName,LastName,Email,PasswordHash,CaptchaCode")] User user)
        {
            if (ModelState.IsValid)
            {
				var password = user.PasswordHash;
				if (ValidatePassword(password))
				{
					user.Role = "User";
					var hasher = new PasswordHasher<User>();
					user.PasswordHash = hasher.HashPassword(user, password);

					if (Captcha.ValidateCaptchaCode(user.CaptchaCode, HttpContext))
					{
						try
						{
							_context.Add(user);
							await _context.SaveChangesAsync();
							return RedirectToAction("UserRegistrationCompleted", "Home");
						}
						catch (Exception)
						{
							return View(user);
						}
					}
					else
					{
						ModelState.AddModelError(string.Empty, "Wrong Captcha Code. Try again!");
						return View(user);
					}
						
				}
				else
				{
					ModelState.AddModelError(string.Empty, "Password must be at least 8 charachters containing uppercase and lowercase letters and at least one number and one special character!");
					return View(user);
				}
                
            }
            return View(user);
        }


		//check password requirements
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







		// GET: User
		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> Index()
		{
			return View(await _context.Users.ToListAsync());
		}

		// GET: User/Details/5
		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> Details(int? id)
		{
			if (id == null)
			{
				return NotFound();
			}

			var user = await _context.Users
				.FirstOrDefaultAsync(m => m.Id == id);
			if (user == null)
			{
				return NotFound();
			}

			return View(user);
		}



		// GET: User/Edit/5
		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _context.Users.FindAsync(id);
            if (user == null)
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
		public async Task<IActionResult> Edit(int id, [Bind("Id,FirstName,LastName,Email,PasswordHash")] User user)
        {
            if (id != user.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(user);
                    await _context.SaveChangesAsync();
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
		public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _context.Users
                .FirstOrDefaultAsync(m => m.Id == id);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        // POST: User/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var user = await _context.Users.FindAsync(id);
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool UserExists(int id)
        {
            return _context.Users.Any(e => e.Id == id);
        }
    }
}
