# persona

[![GoDoc](https://godoc.org/gitote.in/dimensi0n/persona?status.svg)](https://godoc.org/gitote.in/dimensi0n/persona)
[![GoReport](https://goreportcard.com/badge/gitote.in/dimensi0n/persona)](https://goreportcard.com/report/gitote.in/dimensi0n/persona)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://gitote.in/dimensi0n/persona/src/master/LICENSE)

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
3. Does not verify email.

## How to use it

    go get -u gitote.in/dimensi0n/persona
    
Use this model template and add what you want

```golang
type User struct {
	gorm.Model        // REQUIRED
	Username   string // REQUIRED
	Password   string // REQUIRED
	Mail       string `gorm:"not null;unique"` // REQUIRED
	Loggedin   bool   `gorm:"default:false"`   // REQUIRED
}
```

### Config

You'll need to configure Persona. This is an example

```golang
db, err := gorm.Open("sqlite3", "gorm.db")
if err != nil {
	// ERROR
}
defer db.Close()

db.AutoMigrate(&User{})

// If uid field is "username"
// If your users connect them with their username
persona.Config(db, "username")

// If uid field is "email"
// If your users connect them with their email
persona.Config(db, "email")
```

### Signup

```golang
user := User{"Username", "Pasword", "mail@mail.com"}
err := persona.Signup(&user, user.Username, w) // &user is the struct to save && w is the response writer
if err := nil {
    // ERROR 
}
```

### Login

```golang
// Username/Password
user := User{Username: "Username", Password: "Password"}
err := persona.LoginWithUsername(user.Username, user.Password, w) // &user is the struct to save username is the UID field && w is the response writer
if err := nil {
    // ERROR 
}

// Email/Password
user := User{Email: "mail@mail.com", Password: "Password"}
err := persona.LoginWithEmail(user.Mail, user.Password, r) // email is the UID field && r is the request pointer
if err := nil {
    // ERROR 
}
```

### Logout

```golang
user := User{Username: "Username", Password: "Password"}
persona.Logout(user.Username, r) // r is the request pointer
```

### Get current user

```golang
var user User
personna.CurrentUser(&user, r) // r is the request pointer
```
