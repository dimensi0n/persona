package persona

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type User struct {
	gorm.Model        // REQUIRED
	Username   string // REQUIRED
	Password   string // REQUIRED
	Mail       string `gorm:"not null;unique"` // REQUIRED
	Loggedin   bool   `gorm:"default:false"`   // REQUIRED
}

func TestSignup(t *testing.T) {

	w := httptest.NewRecorder()

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	db.DropTable(&User{})
	db.DropTable(&SessionUname{})

	db.AutoMigrate(&User{})

	Config(db, "username")

	user := User{Username: "Erwan", Password: "0000", Mail: "e@e.e"}
	err = Signup(&user, user.Username, w)
	if err != nil {
		t.Error(err)
	}

	resp := w.Result()
	if resp.Header.Get("Set-Cookie") == "" {
		t.Error(errors.New("no session cookie"))
	}
}

func TestLogin(t *testing.T) {

	w := httptest.NewRecorder()

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	Config(db, "username")

	user := User{Username: "Erwan", Password: "0000", Mail: "e@e.e"}

	/*var session SessionUname
	db.Where("username = ?", user.Username).First(&session)

	http.SetCookie(w, &http.Cookie{Name: "test", Value: session.Token})*/
	r := &http.Request{Header: http.Header{}}

	err = Login(user.Username, user.Password, w, r)
	if err != nil {
		t.Error(err)
	}

	database.Table("users").Where("username = ? AND password = ?", "Erwan", "0000").Update(map[string]interface{}{"loggedin": true})
	var newUs User
	database.Table("users").Where("username = ? AND password = ?", user.Username, user.Password).First(&newUs)
	t.Log(newUs)
	println(newUs.Loggedin)
}
