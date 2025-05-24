using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RefreshToken.Api.Models;
using RefreshToken.Api.Services.Auth;
using System.Security.Claims;
using System.Threading.Tasks;
using NetDevPack.Security.Jwt.Core.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using FluentAssertions;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens; // Required for SymmetricSecurityKey
using System.Text; // Required for Encoding

namespace RefreshToken.Api.Tests
{
    [TestClass]
    public class TokenServiceTests
    {
        private Mock<UserManager<IdentityUser>> _mockUserManager;
        private Mock<IJwtService> _mockJwtService;
        private IOptions<AuthSettings> _authSettingsOptions;
        private TokenService _tokenService;

        private IdentityUser _testUser;
        private AuthSettings _testAuthSettings;

        [TestInitialize]
        public void TestInitialize()
        {
            // Mock UserManager
            var store = new Mock<IUserStore<IdentityUser>>();
            _mockUserManager = new Mock<UserManager<IdentityUser>>(store.Object, null, null, null, null, null, null, null, null);

            _testUser = new IdentityUser { UserName = "testuser", Email = "test@example.com", Id = "testuserid" };

            _mockUserManager.Setup(um => um.FindByEmailAsync(It.IsAny<string>()))
                            .ReturnsAsync(_testUser);
            _mockUserManager.Setup(um => um.GetRolesAsync(_testUser))
                            .ReturnsAsync(new List<string> { "User" });
            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser))
                            .ReturnsAsync(new List<Claim>()); // Start with no claims, add as needed per test

            // Mock IJwtService
            _mockJwtService = new Mock<IJwtService>();
            _mockJwtService.Setup(jwt => jwt.GetCurrentSigningCredentials())
                           .ReturnsAsync(new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("TestSecretKey1234567890123456")), SecurityAlgorithms.HmacSha256));

            // Setup AuthSettings
            _testAuthSettings = new AuthSettings
            {
                Secret = "TestSecretKey1234567890123456", // Must be long enough for HS256
                Token = new TokenSettings { ExpiresInSeconds = 3600 },
                RefreshToken = new RefreshTokenSettings { ExpiresInSeconds = 7200 },
                Issuer = "TestIssuer",
                Audience = "TestAudience"
            };
            _authSettingsOptions = Options.Create(_testAuthSettings);

            _tokenService = new TokenService(_mockJwtService.Object, _authSettingsOptions);
        }

        [TestMethod]
        public async Task GenerateAccessToken_ShouldReturnNonEmptyString_WhenUserExists()
        {
            // Arrange
            var userEmail = "test@example.com";

            // Act
            var accessToken = await _tokenService.GenerateAccessToken(_mockUserManager.Object, userEmail);

            // Assert
            accessToken.Should().NotBeNullOrEmpty();
        }

        [TestMethod]
        public async Task GenerateAccessToken_ShouldCallUserManagerAndJwtService()
        {
            // Arrange
            var userEmail = "test@example.com";

            // Act
            await _tokenService.GenerateAccessToken(_mockUserManager.Object, userEmail);

            // Assert
            _mockUserManager.Verify(um => um.FindByEmailAsync(userEmail), Times.Once);
            _mockUserManager.Verify(um => um.GetRolesAsync(_testUser), Times.Once);
            _mockJwtService.Verify(jwt => jwt.GetCurrentSigningCredentials(), Times.Once);
        }

        [TestMethod]
        public async Task GenerateAccessToken_ShouldContainCoreClaims()
        {
            // Arrange
            var userEmail = "test@example.com";
             _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser))
                            .ReturnsAsync(new List<Claim> { new Claim("custom_claim", "custom_value")});


            // Act
            var accessToken = await _tokenService.GenerateAccessToken(_mockUserManager.Object, userEmail);
            var handler = new JwtSecurityTokenHandler();
            var decodedToken = handler.ReadJwtToken(accessToken);

            // Assert
            decodedToken.Issuer.Should().Be(_testAuthSettings.Issuer);
            decodedToken.Audiences.Should().Contain(_testAuthSettings.Audience);
            decodedToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == _testUser.Id);
            decodedToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == userEmail);
            decodedToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Jti); // JTI is random, just check presence
            decodedToken.Claims.Should().Contain(c => c.Type == "role" && c.Value == "User");
            decodedToken.Claims.Should().Contain(c => c.Type == "custom_claim" && c.Value == "custom_value");
        }


        [TestMethod]
        public async Task GenerateRefreshToken_ShouldReturnNonEmptyString_WhenUserExists()
        {
            // Arrange
            var userEmail = "test@example.com";
             _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser)).ReturnsAsync(new List<Claim>());


            // Act
            var refreshToken = await _tokenService.GenerateRefreshToken(_mockUserManager.Object, userEmail);

            // Assert
            refreshToken.Should().NotBeNullOrEmpty();
        }
        
        [TestMethod]
        public async Task GenerateRefreshToken_ShouldUpdateLastRefreshTokenClaim_WhenItDoesNotExist()
        {
            // Arrange
            var userEmail = "test@example.com";
            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser)).ReturnsAsync(new List<Claim>()); // No existing claim

            // Act
            var refreshTokenString = await _tokenService.GenerateRefreshToken(_mockUserManager.Object, userEmail);
            var handler = new JwtSecurityTokenHandler();
            var decodedToken = handler.ReadJwtToken(refreshTokenString);
            var jti = decodedToken.Id;

            // Assert
            _mockUserManager.Verify(um => um.FindByEmailAsync(userEmail), Times.Exactly(2)); // Once for token, once for claim update
            _mockUserManager.Verify(um => um.GetClaimsAsync(_testUser), Times.Once); // For UpdateLastGeneratedClaim
            _mockUserManager.Verify(um => um.AddClaimAsync(_testUser, It.Is<Claim>(c => c.Type == Models.Constants.CustomClaimTypes.LastRefreshToken && c.Value == jti)), Times.Once);
            _mockUserManager.Verify(um => um.ReplaceClaimAsync(It.IsAny<IdentityUser>(), It.IsAny<Claim>(), It.IsAny<Claim>()), Times.Never);
        }

        [TestMethod]
        public async Task GenerateRefreshToken_ShouldReplaceLastRefreshTokenClaim_WhenItExists()
        {
            // Arrange
            var userEmail = "test@example.com";
            var existingJti = "old_jti";
            var existingClaim = new Claim(Models.Constants.CustomClaimTypes.LastRefreshToken, existingJti);
            _mockUserManager.Setup(um => um.GetClaimsAsync(_testUser)).ReturnsAsync(new List<Claim> { existingClaim });

            // Act
            var refreshTokenString = await _tokenService.GenerateRefreshToken(_mockUserManager.Object, userEmail);
            var handler = new JwtSecurityTokenHandler();
            var decodedToken = handler.ReadJwtToken(refreshTokenString);
            var newJti = decodedToken.Id;


            // Assert
            _mockUserManager.Verify(um => um.FindByEmailAsync(userEmail), Times.Exactly(2));
            _mockUserManager.Verify(um => um.GetClaimsAsync(_testUser), Times.Once);
            _mockUserManager.Verify(um => um.ReplaceClaimAsync(_testUser, existingClaim, It.Is<Claim>(c => c.Type == Models.Constants.CustomClaimTypes.LastRefreshToken && c.Value == newJti)), Times.Once);
            _mockUserManager.Verify(um => um.AddClaimAsync(It.IsAny<IdentityUser>(), It.IsAny<Claim>()), Times.Never);
        }
    }
}
