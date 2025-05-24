using Microsoft.AspNetCore.Identity;
using RefreshToken.Api.Models;

namespace RefreshToken.Api.Services.Auth
{
    public interface ITokenService
    {
        Task<string> GenerateAccessToken(UserManager<IdentityUser> userManager, string? email);
        Task<string> GenerateRefreshToken(UserManager<IdentityUser> userManager, string? email);
    }
}
