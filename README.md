## Super auth con Go, verficacion de correo electronico, oauth2-google oauth2-github con Htmx y Fiber

#### to run the project you need to run a postgres db

```bash
docker run --name postgres_db -e POSTGRES_USER=username -e POSTGRES_PASSWORD=password -e POSTGRES_DB=super_db -p 5432:5432 -d postgres
go run main.go
```

-   Template verificacion de email
-   Template email
-   Template signin
-   Template signup
-   Github singin
-   Google signin
-   User profile
-   Update profile
-   Recover password
-   Delete account
