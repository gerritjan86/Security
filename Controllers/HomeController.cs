﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;

namespace WebAppSecurity.Controllers
{
	public class HomeController : Controller
	{

		public IActionResult Index()
		{
			return View();
		}

		public IActionResult Login(Account account)
		{
			return View(account);
		}

		public IActionResult LoggedIn() => View();

		public IActionResult LoggedOut() => View();

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
