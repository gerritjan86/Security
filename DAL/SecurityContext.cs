using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using WebAppSecurity.Models;

namespace WebAppSecurity.DAL
{
	public class SecurityContext : DbContext
	{
		public SecurityContext(DbContextOptions<SecurityContext> options) : base(options) { }

		public DbSet<User> Users { get; set;  }


		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			modelBuilder.Entity<User>()
				.HasIndex(u => u.Email)
				.IsUnique();
		}
	}
}
