#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["MvcTemplate/MvcTemplate.csproj", "MvcTemplate/"]
RUN dotnet restore "MvcTemplate/MvcTemplate.csproj"
COPY . .
WORKDIR "/src/MvcTemplate"
RUN dotnet build "MvcTemplate.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MvcTemplate.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MvcTemplate.dll"]