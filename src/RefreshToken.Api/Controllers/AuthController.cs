//using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using RefreshToken.Api.Services.Auth;
using RefreshToken.Api.Services.Auth.Model;
using RefreshToken.Api.ViewModel.Auth;

namespace RefreshToken.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IJwtService _jwtService;
        private readonly AuthSettings _authSettings;

        public AuthController(ILogger<AuthController> logger
            , SignInManager<IdentityUser> signInManager
            , UserManager<IdentityUser> userManager
            , IJwtService jwtService
            , IConfiguration configuration)
        {
            _logger = logger;
            _signInManager = signInManager;
            _userManager = userManager;
            _jwtService = jwtService;
            _authSettings = configuration.GetSection(nameof(AuthSettings)).Get<AuthSettings>() ?? throw new ArgumentNullException(nameof(AuthSettings));
        }

        [AllowAnonymous]
        [HttpPost("token")]
        public async Task<IActionResult> GetToken(TokenCreateRequestModel model)
        {
            _logger.LogInformation("Token endpoint accessed.");

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, true);

            if (result.IsLockedOut)
                return BadRequest("Account blocked");

            if (!result.Succeeded)
                return BadRequest("Invalid username or password");

            var at = await TokenService.GenerateAccessToken(_userManager, _jwtService, model.Email, _authSettings);
            var rt = await TokenService.GenerateRefreshToken(_userManager, _jwtService, model.Email, _authSettings);

            return Ok(new TokenCreateResponseModel { AccessToken = at, RefreshToken = rt, ExpiresInSeconds = _authSettings.Token.ExpiresInSeconds });
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenCreateRequestModel model)
        {
            _logger.LogInformation("Token endpoint accessed.");

            var handler = new JsonWebTokenHandler();

            var result = handler.ValidateToken(model.RefreshToken, new TokenValidationParameters()
            {
                ValidIssuer = _authSettings.Issuer,
                ValidAudience = _authSettings.Audience,
                RequireSignedTokens = false,
                IssuerSigningKey = await _jwtService.GetCurrentSecurityKey(),
            });

            if (!result.IsValid)
                return BadRequest("Expired token");

            var user = await _userManager.FindByEmailAsync(result.Claims[JwtRegisteredClaimNames.Email].ToString());
            var claims = await _userManager.GetClaimsAsync(user);

            if (!claims.Any(c => c.Type == "LastRefreshToken" && c.Value == result.Claims[JwtRegisteredClaimNames.Jti].ToString()))
                return BadRequest("Expired token");

            if (user.LockoutEnabled)
                if (user.LockoutEnd < DateTime.Now)
                    return BadRequest("User blocked");

            if (claims.Any(c => c.Type == "TenhoQueRelogar" && c.Value == "true"))
                return BadRequest("User must login again");


            var at = await TokenService.GenerateAccessToken(_userManager, _jwtService, result.Claims[JwtRegisteredClaimNames.Email].ToString(), _authSettings);
            var rt = await TokenService.GenerateRefreshToken(_userManager, _jwtService, result.Claims[JwtRegisteredClaimNames.Email].ToString(), _authSettings);

            return Ok(new TokenCreateResponseModel { AccessToken = at, RefreshToken = rt, ExpiresInSeconds = _authSettings.Token.ExpiresInSeconds });
        }
    }
}
