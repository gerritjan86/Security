using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebAppSecurity.DAL;
using WebAppSecurity.Models;
using WebAppSecurity.Models.Captcha;

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

		[Route("get-captcha-image")]
		public IActionResult GetCaptchaImage()
		{
			int width = 100;
			int height = 36;
			var captchaCode = Captcha.GenerateCaptchaCode();
			var result = Captcha.GenerateCaptchaImage(width, height, captchaCode);
			HttpContext.Session.SetString("CaptchaCode", result.CaptchaCode);
			Stream s = new MemoryStream(result.CaptchaByteData);
			return new FileStreamResult(s, "image/png");
		}

		[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
	}
}
