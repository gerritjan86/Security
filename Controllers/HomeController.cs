using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;

namespace WebAppSecurity.Controllers
{
	public class HomeController : Controller
	{

		[AllowAnonymous]
		public IActionResult Index()
		{
			return View();
		}

		[AllowAnonymous]
		public IActionResult LoggedIn() => View();

		[AllowAnonymous]
		public IActionResult LoggedOut() => View();

		[AllowAnonymous]
		public IActionResult UserRegistrationCompleted()
		{
			return View();
		}

		[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
	}
}
