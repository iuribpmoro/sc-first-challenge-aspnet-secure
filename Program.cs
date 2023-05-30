using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

// Libs to fix XSS
using System.Text.RegularExpressions; // to use Regex.IsMatch
using System.Web; // to use HttpUtility.HtmlEncode

// Import Guid
using System;

public class User
{
    public Guid Id { get; set; }
    public string? Name { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
}

public class Comment
{
    public string? Text { get; set; }
}

public static class AuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder app)
    {
        return app.Use(async (context, next) =>
        {
            var userIdString = context.Session.GetString("UserId");

            if (string.IsNullOrEmpty(userIdString))
            {
                context.Response.Redirect("/");
                return;
            }

            await next();
        });
    }
}


public class Startup
{
    private static readonly List<User> users = new List<User>
    {
        new User { Id = Guid.NewGuid(), Name = "Alice", Email = "alice@example.com", Password = "password1" },
        new User { Id = Guid.NewGuid(), Name = "Bob", Email = "bob@example.com", Password = "password2" },
        new User { Id = Guid.NewGuid(), Name = "Charlie", Email = "charlie@example.com", Password = "password3" }
    };

    private static readonly List<Comment> comments = new List<Comment>
    {
        new Comment { Text = "This is a comment" }
    };

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddSession();
        services.AddDistributedMemoryCache();
    }

    private static bool IsWhitelisted(string path)
    {
        var whitelist = new[] { "/", "/login" };
        return whitelist.Contains(path);
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseRouting();

        app.UseSession();

        // Authentication middleware called only when the path is not whitelisted
        app.UseWhen(context => !IsWhitelisted(context.Request.Path), appBuilder =>
        {
            appBuilder.UseAuthenticationMiddleware();
        });

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/", async context =>
            {
                await context.Response.WriteAsync(@"
                    <h1>Welcome to the Store</h1>
                    <form action=""/login"" method=""post"">
                        <label for=""email"">Email:</label>
                        <input type=""email"" name=""email"" id=""email"" required>
                        <label for=""password"">Password:</label>
                        <input type=""password"" name=""password"" id=""password"" required>
                        <button type=""submit"">Login</button>
                    </form>
                ");
            });

            endpoints.MapPost("/login", context =>
            {
                var email = context.Request.Form["email"];
                var password = context.Request.Form["password"];
                var user = users.Find(u => u.Email == email && u.Password == password);

                if (user != null)
                {
                    context.Session.SetString("UserId", user.Id.ToString());
                    context.Response.Redirect($"/user/{user.Id}");
                    return Task.CompletedTask;
                }
                else
                {
                    return context.Response.WriteAsync("Invalid credentials. Please try again.");
                }
            });


            endpoints.MapGet("/user/{id:guid}", context =>
            {
                var requestedUserId = context.Request.RouteValues["id"].ToString();
                var userIdString = context.Session.GetString("UserId");

                if (userIdString != requestedUserId)
                {
                    context.Response.StatusCode = 403; // Forbidden
                    return context.Response.WriteAsync($"Access denied to user {requestedUserId} from user {userIdString}");
                }

                var userId = Guid.Parse(userIdString);
                var user = users.Find(u => u.Id == userId);

                if (user != null)
                {
                    var commentsHtml = string.Join("", comments.ConvertAll(c => $"<li>{HttpUtility.HtmlEncode(c.Text)}</li>"));

                    return context.Response.WriteAsync($@"
                    <h1>User Profile</h1>
                    <p>Name: {user.Name}</p>
                    <p>Email: {user.Email}</p>
                    <h2>Write a comment:</h2>
                    <form action=""/comments"" method=""post"">
                        <input type=""text"" name=""comment"" id=""comment"">
                        <button type=""submit"">Send</button>
                    </form>
                    <h2>Comments:</h2>
                    <ul>
                        {commentsHtml}
                    </ul>
                    <script>
                        var form = document.querySelector('form');
                        form.addEventListener('submit', function(event) {{
                            event.preventDefault();
                            var comment = document.getElementById('comment').value;
                            var xhr = new XMLHttpRequest();
                            xhr.open('POST', '/comments');
                            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                            xhr.send('comment=' + encodeURIComponent(comment));

                            // After submit, reloads page to show the new comment
                            window.location.reload();
                        }});
                    </script>
                ");
                }

                context.Response.StatusCode = 404;
                return context.Response.WriteAsync("User not found");
            });

            endpoints.MapPost("/comments", context =>
            {
                if (context.Session.TryGetValue("UserId", out var userIdBytes))
                {
                    var userId = BitConverter.ToInt32(userIdBytes);
                    var commentText = context.Request.Form["comment"];

                    // If Regex.IsMatch not alphanumerical, shows error message
                    string pattern = @"^[a-zA-Z0-9\s]*$";
                    if (!Regex.IsMatch(commentText, pattern))
                    {
                        return context.Response.WriteAsync("Invalid comment. Please try again.");
                    }
                    else
                    {
                        comments.Add(new Comment { Text = commentText });
                        context.Response.Redirect($"/user/{userId}");
                        return System.Threading.Tasks.Task.CompletedTask;
                    }
                }
                else
                {
                    context.Response.Redirect("/");
                    return System.Threading.Tasks.Task.CompletedTask;
                }
            });
        });
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
}
