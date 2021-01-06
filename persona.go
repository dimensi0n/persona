// Package persona provides user mangement fonctions
package persona

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	maths "math/rand"
	"net/http"
	"time"

	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
)

// User default struct
type User struct {
	gorm.Model        // REQUIRED
	Username   string `gorm:"not null;unique"` // REQUIRED
	Password   string // REQUIRED
	Mail       string `gorm:"not null;unique"` // REQUIRED
	Loggedin   bool   `gorm:"default:true"`    // REQUIRED
}

// Sessionusername struct
type Sessionusername struct {
	gorm.Model
	Username string `gorm:"not null;"`
	Token    string
}

// Sessionemail struct
type Sessionemail struct {
	gorm.Model
	Mail  string `gorm:"not null;unique"`
	Token string
}

var (
	database *gorm.DB
	suid     string
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[maths.Intn(len(letterBytes))]
	}
	return string(b)
}

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func createCookie(username string, w http.ResponseWriter) error {
	key := []byte(randStringBytes(32))

	encrypted, err := encrypt(key, username)
	if err != nil {
		return err
	}

	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{Name: "session-persona", Value: encrypted, Expires: expiration}
	if w == nil {
		return errors.New("response writer is not nullable")
	}
	http.SetCookie(w, &cookie)

	if suid == "username" {
		var user Sessionusername
		database.Table("sessionusernames").Where("username = ?", username).First(&user).Delete(&user)
		userSession := Sessionusername{Username: username, Token: encrypted}
		database.Create(&userSession)
	} else if suid == "email" {
		var user Sessionemail
		database.Table("sessionemails").Where("mail = ?", username).First(&user).Delete(&user)
		userSession := Sessionemail{Mail: username, Token: encrypted}
		database.Create(&userSession)
	}

	return nil
}

// Config Persona
func Config(db *gorm.DB, newUID string) {
	database = db
	suid = newUID
	if suid == "username" {
		database.AutoMigrate(&Sessionusername{})
	} else if suid == "email" {
		database.AutoMigrate(&Sessionemail{})
	}
}

// HashPassword hashes the password before saving it
func HashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes)
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Signup register the user
func Signup(user interface{}, username string, w http.ResponseWriter) error {
	createCookie(username, w)

	database.Create(user)

	return nil
}

// Login logs in the user
func Login(uid string, password string, w http.ResponseWriter) error {
	if suid == "username" {
		var user User
		if !database.Table("users").Where("username = ?", uid).First(&user).RecordNotFound() {
			passwordVerified := checkPasswordHash(password, user.Password)
			if passwordVerified {
				if err := createCookie(uid, w); err != nil {
					return err
				}
				database.Table("users").Where("username = ?", uid).Update(map[string]interface{}{"loggedin": true})
			}
		} else {
			return errors.New("user doesn't exist")
		}
	} else if suid == "email" {
		var user User
		if !database.Table("users").Where("mail = ?", uid).First(&user).RecordNotFound() {
			passwordVerified := checkPasswordHash(password, user.Password)
			if passwordVerified {
				if err := createCookie(uid, w); err != nil {
					return err
				}
				database.Table("users").Where("mail = ?", uid).Update(map[string]interface{}{"loggedin": true})
			}
		} else {
			return errors.New("user doesn't exist")
		}
	}

	return nil
}

// Logout logs out the user
func Logout(uid string, w http.ResponseWriter) error {
	if suid == "username" {
		var session Sessionusername
		database.Table("sessionusernames").Where("username = ?", uid).First(&session).Delete(&session)
		http.SetCookie(w, &http.Cookie{Name: "session-persona", Expires: time.Unix(0, 0)})
	} else if suid == "email" {
		var session Sessionemail
		database.Table("sessionemails").Where("mail = ?", uid).First(&session).Delete(&session)
		http.SetCookie(w, &http.Cookie{Name: "session-persona", Expires: time.Unix(0, 0)})
	}
	return nil
}

// GetCurrentUser returns current user username/email
func GetCurrentUser(r *http.Request) (string, error) {
	if suid == "username" {
		cookie, _ := r.Cookie("session-persona")
		var session Sessionusername
		database.Table("sessionusernames").Where("token = ?", cookie.Value).First(&session)
		if (Sessionusername{}) == session {
			return "", errors.New("no user loggedin")
		}
		return session.Username, nil
	} else if suid == "email" {
		cookie, _ := r.Cookie("session-persona")
		var session Sessionemail
		database.Table("sessionemails").Where("token = ?", cookie.Value).First(&session)
		if (Sessionemail{}) == session {
			return "", errors.New("no user loggedin")
		}
		return session.Mail, nil
	}
	return "", nil
}

// RecoverPassword recovers the user password
func RecoverPassword(uid string, oldPassword string, newPassword string) error {
	if suid == "username" {
		var user User
		if !database.Table("users").Where("username = ?", uid).First(&user).RecordNotFound() {
			passwordVerified := checkPasswordHash(oldPassword, user.Password)
			if passwordVerified {
				database.Table("users").Where("username = ?", uid).Update(map[string]interface{}{"password": HashPassword(newPassword)})
			}
		} else {
			return errors.New("user doesn't exist")
		}
	} else if suid == "email" {
		var user User
		if !database.Table("users").Where("mail = ?", uid).First(&user).RecordNotFound() {
			passwordVerified := checkPasswordHash(oldPassword, user.Password)
			if passwordVerified {
				database.Table("users").Where("mail = ?", uid).Update(map[string]interface{}{"password": HashPassword(newPassword)})
			}
		} else {
			return errors.New("user doesn't exist")
		}
	}
	return nil
}
