//using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using RefreshToken.Api.Models.Constants; // Added using for CustomClaimTypes
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
        private readonly IJwtService _jwtService; // Still needed for refresh token validation
        private readonly AuthSettings _authSettings; // Still needed for refresh token validation and Expiry
        private readonly ITokenService _tokenService; // New service

        public AuthController(ILogger<AuthController> logger
            , SignInManager<IdentityUser> signInManager
            , UserManager<IdentityUser> userManager
            , IJwtService jwtService
            , Microsoft.Extensions.Options.IOptions<AuthSettings> authSettingsOptions // Changed from IConfiguration
            , ITokenService tokenService) // Added tokenService
        {
            _logger = logger;
            _signInManager = signInManager;
            _userManager = userManager;
            _jwtService = jwtService;
            _authSettings = authSettingsOptions.Value; // Get AuthSettings from IOptions
            _tokenService = tokenService; // Assign injected service
        }

        /// <summary>
        /// Authenticates a user and returns an access token and a refresh token.
        /// </summary>
        /// <param name="model">The login credentials (email and password).</param>
        /// <returns>An access token, refresh token, and token expiry information if authentication is successful.</returns>
        /// <response code="200">Authentication successful, tokens returned.</response>
        /// <response code="400">Invalid credentials, account locked out, or other authentication failure.</response>
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

            var at = await _tokenService.GenerateAccessToken(_userManager, model.Email); // Use injected service
            var rt = await _tokenService.GenerateRefreshToken(_userManager, model.Email); // Use injected service

            return Ok(new TokenCreateResponseModel { AccessToken = at, RefreshToken = rt, ExpiresInSeconds = _authSettings.Token.ExpiresInSeconds });
        }

        /// <summary>
        /// Refreshes an access token using a valid refresh token.
        /// </summary>
        /// <param name="model">The refresh token model containing the refresh token string.</param>
        /// <returns>A new access token, a new refresh token, and token expiry information if the refresh token is valid.</returns>
        /// <response code="200">Token refresh successful, new tokens returned.</response>
        /// <response code="400">Invalid or expired refresh token, user account issues (locked out, requires re-authentication), or other validation failures.</response>
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
                return BadRequest("Invalid refresh token."); // Changed error message

            var user = await _userManager.FindByEmailAsync(result.Claims[JwtRegisteredClaimNames.Email].ToString());
            var claims = await _userManager.GetClaimsAsync(user);

            // Check if the refresh token JTI matches the one stored for the user.
            // This helps prevent refresh token reuse.
            if (!claims.Any(c => c.Type == CustomClaimTypes.LastRefreshToken && c.Value == result.Claims[JwtRegisteredClaimNames.Jti].ToString()))
                return BadRequest("Refresh token has been invalidated or already used."); // Changed error message

            if (user.LockoutEnabled && user.LockoutEnd >= DateTimeOffset.UtcNow) // Adjusted lockout check
                    return BadRequest("Account is locked out."); // Changed error message

            // Check if the user has a claim requiring them to re-authenticate.
            // This claim might be set by an administrator if suspicious activity is detected
            // or if a user's profile details that impact security have changed significantly.
            if (claims.Any(c => c.Type == CustomClaimTypes.ForceReAuthentication && c.Value == "true")) // Updated claim name
                return BadRequest("User must login again");


            var at = await _tokenService.GenerateAccessToken(_userManager, result.Claims[JwtRegisteredClaimNames.Email].ToString()); // Use injected service
            var rt = await _tokenService.GenerateRefreshToken(_userManager, result.Claims[JwtRegisteredClaimNames.Email].ToString()); // Use injected service

            return Ok(new TokenCreateResponseModel { AccessToken = at, RefreshToken = rt, ExpiresInSeconds = _authSettings.Token.ExpiresInSeconds });
        }
    }
}
