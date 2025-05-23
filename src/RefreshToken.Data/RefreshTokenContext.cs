﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RefreshToken.Data
{
    public class RefreshTokenContext : IdentityDbContext
    {
        public RefreshTokenContext(DbContextOptions<RefreshTokenContext> options) : base(options) { }
    }
}
