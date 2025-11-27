# 1. BUILD STAGE
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy the csproj and restore dependencies
COPY ["src/IdP.Web/IdP.Web.csproj", "src/IdP.Web/"]
RUN dotnet restore "src/IdP.Web/IdP.Web.csproj"

# Copy the rest of the code
COPY . .
WORKDIR "/src/src/IdP.Web"

# Build and Publish
RUN dotnet build "IdP.Web.csproj" -c Release -o /app/build
RUN dotnet publish "IdP.Web.csproj" -c Release -o /app/publish

# 2. RUN STAGE
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Copy the build artifacts from the build stage
COPY --from=build /app/publish .

# Set the entry point
ENTRYPOINT ["dotnet", "IdP.Web.dll"]