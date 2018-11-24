package persona

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	maths "math/rand"
	"net/http"
	"time"

	"github.com/jinzhu/gorm"
)

// Session struct
type Session struct {
	gorm.Model
	Username string
	Key      []byte
	Token    string
}

var database *gorm.DB

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

// Config Persona
func Config(db *gorm.DB) {
	database = db
	database.AutoMigrate(&Session{})
}

// Signup register the user
func Signup(user interface{}, username string, w http.ResponseWriter) error {
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

	userSession := Session{Username: username, Key: key, Token: encrypted}
	database.Create(&userSession)

	database.Create(user)

	return nil
}

// LoginWithUsername logs in user with username
func LoginWithUsername(username string, password string, w http.ResponseWriter) error {
	fmt.Printf("%s", username)
	return nil
}

// LoginWithEmail logs in user with email
func LoginWithEmail(email string, password string, w http.ResponseWriter) error {
	fmt.Printf("%s", email)
	return nil
}
