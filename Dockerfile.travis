FROM microsoft/aspnetcore:1.1
ENV DefaultConnection="Data Source=mindpalace\\,1434;Initial Catalog=com.moonlay.auth;Persist Security Info=True;User ID=sa;Password=Admin-pwd;MultipleActiveResultSets=True"
ENV ASPNETCORE_ENVIRONMENT=Production
WORKDIR App
EXPOSE 80
COPY Com.Moonlay.Service.Auth.WebApi/bin/publish/. .
ENTRYPOINT ["dotnet","Com.Moonlay.Service.Auth.WebApi.dll"]