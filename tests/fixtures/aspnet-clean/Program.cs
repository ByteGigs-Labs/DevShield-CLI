var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddPolicy("web", p => p.WithOrigins("https://example.com")));
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
}
app.UseCors("web");
app.MapControllers();
app.Run();
