using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using RefreshToken.Api.Models; // Changed from RefreshToken.Api.Services.Auth.Model
using RefreshToken.Api.Models.Constants; // Added using for CustomClaimTypes
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RefreshToken.Api.Services.Auth
{
    public class TokenService : ITokenService
    {
        private readonly IJwtService _jwtService;
        private readonly AuthSettings _authSettings;

        public TokenService(IJwtService jwtService, IOptions<AuthSettings> authSettingsOptions)
        {
            _jwtService = jwtService;
            _authSettings = authSettingsOptions.Value;
        }

        public async Task<string> GenerateAccessToken(UserManager<IdentityUser> userManager, string? email)
        {
            var user = await userManager.FindByEmailAsync(email);
            var userRoles = await userManager.GetRolesAsync(user);

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(await userManager.GetClaimsAsync(user));
            identityClaims.AddClaims(userRoles.Select(s => new Claim("role", s)));
            identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            var handler = new JwtSecurityTokenHandler();

            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _authSettings.Issuer, // Use injected settings
                Audience = _authSettings.Audience, // Use injected settings
                SigningCredentials = await _jwtService.GetCurrentSigningCredentials(), // Use injected IJwtService
                Subject = identityClaims,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddSeconds(_authSettings.Token.ExpiresInSeconds), // Use injected settings
                IssuedAt = DateTime.UtcNow,
                TokenType = "at+jwt"
            });

            var encodedJwt = handler.WriteToken(securityToken);

            return encodedJwt;
        }

        public async Task<string> GenerateRefreshToken(UserManager<IdentityUser> userManager, string? email)
        {
            var jti = Guid.NewGuid().ToString();
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, jti)
            };

            // Necessary to convert to IdentityClaims
            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var handler = new JwtSecurityTokenHandler();

            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _authSettings.Issuer, // Use injected settings
                Audience = _authSettings.Audience, // Use injected settings
                SigningCredentials = await _jwtService.GetCurrentSigningCredentials(), // Use injected IJwtService
                Subject = identityClaims,
                NotBefore = DateTime.Now,
                Expires = DateTime.Now.AddSeconds(_authSettings.RefreshToken.ExpiresInSeconds), // Use injected settings
                TokenType = "rt+jwt"
            });
            await UpdateLastGeneratedClaim(userManager, email, jti);
            var encodedJwt = handler.WriteToken(securityToken);
            return encodedJwt;
        }

        private static async Task UpdateLastGeneratedClaim(UserManager<IdentityUser> userManager, string? email, string jti)
        {
            var user = await userManager.FindByEmailAsync(email);
            var claims = await userManager.GetClaimsAsync(user);
            var newLastRtClaim = new Claim(CustomClaimTypes.LastRefreshToken, jti);

            var claimLastRt = claims.FirstOrDefault(f => f.Type == CustomClaimTypes.LastRefreshToken);

            if (claimLastRt != null)
                await userManager.ReplaceClaimAsync(user, claimLastRt, newLastRtClaim);
            else
                await userManager.AddClaimAsync(user, newLastRtClaim);

        }
    }
}
