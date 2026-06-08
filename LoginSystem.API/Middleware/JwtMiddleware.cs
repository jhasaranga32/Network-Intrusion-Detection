using LoginSystem.API.Repositories.Interfaces;
using LoginSystem.API.Services;

namespace LoginSystem.API.Middleware;

/// <summary>
/// Attaches the user to context if a valid JWT is present.
/// Works alongside the built-in JWT bearer authentication.
/// </summary>
public class JwtMiddleware
{
    private readonly RequestDelegate _next;

    public JwtMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, JwtService jwtService, IUserRepository userRepository)
    {
        var token = context.Request.Headers["Authorization"]
            .FirstOrDefault()?.Split(" ").Last();

        if (!string.IsNullOrEmpty(token))
        {
            var principal = jwtService.ValidateToken(token);
            if (principal != null)
            {
                context.User = principal;
            }
        }

        await _next(context);
    }
}
