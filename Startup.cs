﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebAppSecurity.DAL;
using Pomelo.EntityFrameworkCore.MySql;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;
using WebAppSecurity.Models;
using Joonasw.AspNetCore.SecurityHeaders;

namespace WebAppSecurity
{
	public class Startup
	{
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		public static string ConnectionString { get; private set; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			services.Configure<CookiePolicyOptions>(options =>
			{
				// This lambda determines whether user consent for non-essential cookies is needed for a given request.
				options.CheckConsentNeeded = context => true;
				options.MinimumSameSitePolicy = SameSiteMode.None;
			});

			//Pomelo installeren en dan  options.UseMySql gebruiken in plaats van options.UseSqlServer
			//AddDbContext of AddDbContextPool???
			services.AddDbContext<SecurityContext>(options => options.UseMySql(
				Configuration.GetConnectionString("DefaultConnectionMaria"),
				mysqlOptions => { mysqlOptions.ServerVersion(new Version(5, 7, 17), ServerType.MariaDb); }
			));


			//handige link: https://docs.microsoft.com/en-us/aspnet/core/migration/1x-to-2x/identity-2x?view=aspnetcore-3.0
			services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
					.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
					{
						options.LoginPath = "/User/Login";
					});


			// Need this service for Session Id and for the Captcha to work
			services.AddSession(options =>
			{
				options.IdleTimeout = TimeSpan.FromMinutes(20);
				options.Cookie.HttpOnly = true;
			});
			services.AddMemoryCache();

			services.AddCors(options =>
			{
				options.AddPolicy("MyPolicy", builder =>
				{
					builder.WithOrigins("https://localhost:44322", "https://localhost:5001", "https://145.44.234.246");
				});
			});

			services.AddCsp(nonceByteAmount: 32);

			services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IHostingEnvironment env, SecurityContext context)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
				// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
				app.UseHsts(new Joonasw.AspNetCore.SecurityHeaders.HstsOptions(TimeSpan.FromDays(30), includeSubDomains: false, preload: false));
			}

			ConnectionString = Configuration.GetConnectionString("DefaultConnectionMaria");

			app.UseCors("MyPolicy");
			app.UseCsp(csp =>
			{
				csp.AllowScripts
					.FromSelf()
					.From("https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.bundle.min.js")
					.From("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js")
					.From("https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.17.0/jquery.validate.min.js")
					.From("https://cdnjs.cloudflare.com/ajax/libs/jquery-validation-unobtrusive/3.2.11/jquery.validate.unobtrusive.min.js")
					.AddNonce(); //this domain

			});

			app.UseHttpsRedirection();
			app.UseStaticFiles();
			app.UseCookiePolicy();
			app.UseAuthentication();
			app.UseSession();

			app.UseMvc(routes =>
			{
				routes.MapRoute(
					name: "default",
					template: "{controller=Home}/{action=Index}/{id?}");
			});
			SeedData.Initialize(context);
		}
	}
}
