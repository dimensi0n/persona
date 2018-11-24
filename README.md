# persona

> User management library written in Go

## What is Persona?

Persona is a simple, functional service to let you **create**, **verify** and **update** user profiles.

Persona is not for everyone; if your login system is too complex and relies on many factors, Persona is not for you. **However, persona works great for most use cases**.

## What does it do?
1. Helps you register new users.
3. Validates credentials on login.
5. Allows changing passwords.
6. Allows recovering forgotten passwords.
7. Create sessions

## What does it NOT do?
3. Does not verify email

## How to use it

    go get -u gitote.in/dimensi0n/persona
    
Use this model template and add what you want

```golang
type User struct {
    gorm.Model       // REQUIRED
    Username  string // REQUIRED
    Password  string // REQUIRED
    Mail      string // REQUIRED
    Session   string // REQUIRED
}
```

### Signup

```golang
user := User{"Username", "Pasword", "mail@mail.com"}
err := persona.Signup(&user)
if err := nil {
    // ERROR 
}
```

### Login

```golang
// Username/Password
user := User{Username: "Username", Password: "Password"}
err := persona.Login(&user, "username")
if err := nil {
    // ERROR 
}

// Email/Password
user := User{Email: "mail@mail.com", Password: "Password"}
err := persona.Login(&user, "email")
if err := nil {
    // ERROR 
}
```

### Get current user

```golang
var user User
personna.CurrentUser(&user)
```
