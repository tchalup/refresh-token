using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace RefreshToken.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ProtectedController : ControllerBase
    {
        private readonly ILogger<ProtectedController> _logger;

        public ProtectedController(ILogger<ProtectedController> logger) => _logger = logger;

        /// <summary>
        /// Accesses a protected endpoint that requires authorization.
        /// </summary>
        /// <remarks>
        /// This endpoint can only be accessed by users who provide a valid JWT access token.
        /// It returns a success message along with the claims associated with the authenticated user.
        /// </remarks>
        /// <returns>An HTTP 200 OK response with a success message and user claims if authorized.</returns>
        /// <response code="200">Successfully accessed the protected endpoint. User claims are returned.</response>
        /// <response code="401">Unauthorized if no token or an invalid token is provided.</response>
        [Authorize]
        [HttpGet("")]
        public IActionResult Index()
        {
            _logger.LogInformation("Protected endpoint accessed.");

            return Ok($"This is a protected endpoint.\nYou are authorized to access it\n.{string.Join("-", HttpContext.User.Claims.Select(x => $"Tipo: {x.Type} | Valor: {x.Value}\n").ToArray())}");
        }
    }
}
