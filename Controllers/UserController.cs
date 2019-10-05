using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;

namespace WebAppSecurity.Controllers
{
    public class UserController : Controller
    {
        private readonly SecurityContext _context;

        public UserController(SecurityContext context)
        {
            _context = context;
        }

		//GET User/Login
		//Login view where user can fill in his emailaddress and password
		[HttpGet]
		public IActionResult Login() => View();


		//POST User/Login
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		[HttpPost]
		public IActionResult Login([Bind("Email,PasswordHash")] User user)
		{
			User userDb = _context.Users.FirstOrDefault(u => u.Email.Equals(user.Email));

			if (userDb == null)
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(user);
			}

			if (user.Email.Equals(string.Empty) || user.PasswordHash.Equals(string.Empty))
			{
				ModelState.AddModelError(string.Empty, "Try again!");
				return View(user);
			}

			if (!user.Email.Equals(string.Empty) && !user.PasswordHash.Equals(string.Empty))
			{
				PasswordHasher<User> passwordHasher = new PasswordHasher<User>();
				PasswordVerificationResult verificationResult = passwordHasher.VerifyHashedPassword(userDb, userDb.PasswordHash, user.PasswordHash);

				if (verificationResult == PasswordVerificationResult.Success)
				{
					return RedirectToAction("LoggedIn", "Home");
				}
				else
				{
					ModelState.AddModelError(string.Empty, "Try again!");
					return View(user);
				}
			}

			ModelState.AddModelError(string.Empty, "Try again!");
			return View(user);
			//return RedirectToAction("Login", "Home", user);
		}



		// GET: User/Create
		public IActionResult Create()
        {
            return View();
        }


        // POST: User/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,FirstName,LastName,Email,PasswordHash")] User user)
        {
            if (ModelState.IsValid)
            {
				var password = user.PasswordHash;
				if (ValidatePassword(password))
				{
					user.Role = "User";
					var hasher = new PasswordHasher<User>();
					user.PasswordHash = hasher.HashPassword(user, password);
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
		public async Task<IActionResult> Index()
		{
			return View(await _context.Users.ToListAsync());
		}

		// GET: User/Details/5
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
