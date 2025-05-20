using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace GoogleAuthentication.Data
{
    public class AppDbContext : IdentityDbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }
    }