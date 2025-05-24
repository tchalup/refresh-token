using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RefreshToken.Api.Controllers;
using RefreshToken.Api.Models;
using RefreshToken.Api.Services.Auth;
using RefreshToken.Api.ViewModel.Auth;
using System.Threading.Tasks;
using FluentAssertions;
using System.Security.Claims;
using System.Collections.Generic;
using System;
using System.IdentityModel.Tokens.Jwt; // For JwtRegisteredClaimNames
using NetDevPack.Security.Jwt.Core.Interfaces; // For IJwtService
using Microsoft.IdentityModel.Tokens; // For TokenValidationParameters, SecurityKey
using System.Text; // For Encoding

namespace RefreshToken.Api.Tests
{
    [TestClass]
    public class AuthControllerTests
    {
        private Mock<ITokenService> _mockTokenService;
        private Mock<UserManager<IdentityUser>> _mockUserManager;
        private Mock<SignInManager<IdentityUser>> _mockSignInManager;
        private Mock<ILogger<AuthController>> _mockLogger;
        private IOptions<AuthSettings> _authSettingsOptions;
        private Mock<IJwtService> _mockJwtService; // For RefreshToken validation part

        private AuthController _authController;
        private AuthSettings _testAuthSettings;
        private IdentityUser _testUser;

        [TestInitialize]
        public void TestInitialize()
        {
            _mockTokenService = new Mock<ITokenService>();

            // Mock UserManager
            var userStoreMock = new Mock<IUserStore<IdentityUser>>();
            _mockUserManager = new Mock<UserManager<IdentityUser>>(userStoreMock.Object, null, null, null, null, null, null, null, null);

            // Mock SignInManager
            var contextAccessorMock = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            var userClaimsPrincipalFactoryMock = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
            _mockSignInManager = new Mock<SignInManager<IdentityUser>>(_mockUserManager.Object, contextAccessorMock.Object, userClaimsPrincipalFactoryMock.Object, null, null, null, null);

            _mockLogger = new Mock<ILogger<AuthController>>();
            _mockJwtService = new Mock<IJwtService>();


            _testAuthSettings = new AuthSettings
            {
                Secret = "TestSecretKey1234567890123456",
                Token = new TokenSettings { ExpiresInSeconds = 3600 },
                RefreshToken = new RefreshTokenSettings { ExpiresInSeconds = 7200 },
                Issuer = "TestIssuer",
                Audience = "TestAudience"
            };
            _authSettingsOptions = Options.Create(_testAuthSettings);

            _testUser = new IdentityUser { UserName = "testuser", Email = "test@example.com", Id = "testuserid" };

            // Default Setups
            _mockTokenService.Setup(s => s.GenerateAccessToken(It.IsAny<UserManager<IdentityUser>>(), It.IsAny<string>()))
                             .ReturnsAsync("sample_access_token");
            _mockTokenService.Setup(s => s.GenerateRefreshToken(It.IsAny<UserManager<IdentityUser>>(), It.IsAny<string>()))
                             .ReturnsAsync("sample_refresh_token");

            _mockUserManager.Setup(um => um.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(_testUser);
            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser)).ReturnsAsync(new List<Claim>());


            _authController = new AuthController(
                _mockLogger.Object,
                _mockSignInManager.Object,
                _mockUserManager.Object,
                _mockJwtService.Object, // Added for RefreshToken validation
                _authSettingsOptions,
                _mockTokenService.Object
            );
        }

        // --- GetToken Tests ---

        [TestMethod]
        public async Task GetToken_SuccessfulLogin_ReturnsOkWithTokens()
        {
            // Arrange
            var loginModel = new TokenCreateRequestModel { Email = "test@example.com", Password = "password" };
            _mockSignInManager.Setup(s => s.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, true))
                              .ReturnsAsync(SignInResult.Success);

            // Act
            var result = await _authController.GetToken(loginModel);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var okResult = result as OkObjectResult;
            okResult.Value.Should().BeOfType<TokenCreateResponseModel>();
            var tokenResponse = okResult.Value as TokenCreateResponseModel;
            tokenResponse.AccessToken.Should().Be("sample_access_token");
            tokenResponse.RefreshToken.Should().Be("sample_refresh_token");
            tokenResponse.ExpiresInSeconds.Should().Be(_testAuthSettings.Token.ExpiresInSeconds);
        }

        [TestMethod]
        public async Task GetToken_LockedOut_ReturnsBadRequest()
        {
            // Arrange
            var loginModel = new TokenCreateRequestModel { Email = "test@example.com", Password = "password" };
            _mockSignInManager.Setup(s => s.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, true))
                              .ReturnsAsync(SignInResult.LockedOut);

            // Act
            var result = await _authController.GetToken(loginModel);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Value.Should().Be("Account blocked");
        }

        [TestMethod]
        public async Task GetToken_InvalidCredentials_ReturnsBadRequest()
        {
            // Arrange
            var loginModel = new TokenCreateRequestModel { Email = "test@example.com", Password = "password" };
            _mockSignInManager.Setup(s => s.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, true))
                              .ReturnsAsync(SignInResult.Failed);

            // Act
            var result = await _authController.GetToken(loginModel);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Value.Should().Be("Invalid username or password");
        }

        // --- RefreshToken Tests ---
        // Helper to generate a basic JWT for testing refresh token validation
        private string GenerateTestJwt(List<Claim> claims, DateTime expires)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_testAuthSettings.Secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _testAuthSettings.Issuer,
                audience: _testAuthSettings.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: credentials);
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [TestMethod]
        public async Task RefreshToken_Successful_ReturnsOkWithNewTokens()
        {
            // Arrange
            var jti = Guid.NewGuid().ToString();
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, _testUser.Email),
                new Claim(JwtRegisteredClaimNames.Jti, jti)
            };
            var validRefreshToken = GenerateTestJwt(claims, DateTime.UtcNow.AddMinutes(30));
            var refreshTokenModel = new RefreshTokenCreateRequestModel { RefreshToken = validRefreshToken };

            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser))
                            .ReturnsAsync(new List<Claim> { new Claim(Models.Constants.CustomClaimTypes.LastRefreshToken, jti) });
            
            _mockJwtService.Setup(s => s.GetCurrentSecurityKey()).ReturnsAsync(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_testAuthSettings.Secret)));


            // Act
            var result = await _authController.RefreshToken(refreshTokenModel);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var okResult = result as OkObjectResult;
            okResult.Value.Should().BeOfType<TokenCreateResponseModel>();
            var tokenResponse = okResult.Value as TokenCreateResponseModel;
            tokenResponse.AccessToken.Should().Be("sample_access_token");
            tokenResponse.RefreshToken.Should().Be("sample_refresh_token");
        }

        [TestMethod]
        public async Task RefreshToken_InvalidToken_ReturnsBadRequest()
        {
            // Arrange
            // Using an expired token to simulate invalid token for simplicity with ValidateToken
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, _testUser.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var expiredRefreshToken = GenerateTestJwt(claims, DateTime.UtcNow.AddMinutes(-30)); // Expired
            var refreshTokenModel = new RefreshTokenCreateRequestModel { RefreshToken = expiredRefreshToken };
            
            _mockJwtService.Setup(s => s.GetCurrentSecurityKey()).ReturnsAsync(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_testAuthSettings.Secret)));


            // Act
            var result = await _authController.RefreshToken(refreshTokenModel);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Value.Should().Be("Invalid refresh token.");
        }

        [TestMethod]
        public async Task RefreshToken_JtiMismatch_ReturnsBadRequest()
        {
            // Arrange
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, _testUser.Email),
                new Claim(JwtRegisteredClaimNames.Jti, "token_jti")
            };
            var validRefreshToken = GenerateTestJwt(claims, DateTime.UtcNow.AddMinutes(30));
            var refreshTokenModel = new RefreshTokenCreateRequestModel { RefreshToken = validRefreshToken };

            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser))
                            .ReturnsAsync(new List<Claim> { new Claim(Models.Constants.CustomClaimTypes.LastRefreshToken, "different_jti") });
            _mockJwtService.Setup(s => s.GetCurrentSecurityKey()).ReturnsAsync(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_testAuthSettings.Secret)));


            // Act
            var result = await _authController.RefreshToken(refreshTokenModel);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Value.Should().Be("Refresh token has been invalidated or already used.");
        }

        [TestMethod]
        public async Task RefreshToken_UserLockedOut_ReturnsBadRequest()
        {
            // Arrange
             var jti = Guid.NewGuid().ToString();
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, _testUser.Email),
                new Claim(JwtRegisteredClaimNames.Jti, jti)
            };
            var validRefreshToken = GenerateTestJwt(claims, DateTime.UtcNow.AddMinutes(30));
            var refreshTokenModel = new RefreshTokenCreateRequestModel { RefreshToken = validRefreshToken };
            
            _testUser.LockoutEnabled = true;
            _testUser.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
            _mockUserManager.Setup(um => um.FindByEmailAsync(_testUser.Email)).ReturnsAsync(_testUser);
            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser))
                            .ReturnsAsync(new List<Claim> { new Claim(Models.Constants.CustomClaimTypes.LastRefreshToken, jti) });
            _mockJwtService.Setup(s => s.GetCurrentSecurityKey()).ReturnsAsync(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_testAuthSettings.Secret)));


            // Act
            var result = await _authController.RefreshToken(refreshTokenModel);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Value.Should().Be("Account is locked out.");
        }

        [TestMethod]
        public async Task RefreshToken_ForceReAuthentication_ReturnsBadRequest()
        {
            // Arrange
            var jti = Guid.NewGuid().ToString();
            var tokenClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, _testUser.Email),
                new Claim(JwtRegisteredClaimNames.Jti, jti)
            };
            var validRefreshToken = GenerateTestJwt(tokenClaims, DateTime.UtcNow.AddMinutes(30));
            var refreshTokenModel = new RefreshTokenCreateRequestModel { RefreshToken = validRefreshToken };

            var userClaims = new List<Claim>
            {
                new Claim(Models.Constants.CustomClaimTypes.LastRefreshToken, jti),
                new Claim(Models.Constants.CustomClaimTypes.ForceReAuthentication, "true")
            };
            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser)).ReturnsAsync(userClaims);
            _mockJwtService.Setup(s => s.GetCurrentSecurityKey()).ReturnsAsync(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_testAuthSettings.Secret)));


            // Act
            var result = await _authController.RefreshToken(refreshTokenModel);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Value.Should().Be("User must login again");
        }
    }
}
