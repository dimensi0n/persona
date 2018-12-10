package persona

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

func TestSignup(t *testing.T) {

	w := httptest.NewRecorder()

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	db.DropTable(&User{})
	db.DropTable(&Sessionusername{})

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

func TestLogout(t *testing.T) {
	w := httptest.NewRecorder()

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	Config(db, "username")

	user := User{Username: "Erwan", Password: "0000", Mail: "e@e.e"}

	err = Logout(user.Username, w)
	if err != nil {
		t.Error(err)
	}

	resp := w.Result()
	if resp.Cookies()[0].Value != "" {
		t.Error(errors.New(resp.Cookies()[0].Value))
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

	err = Login(user.Username, user.Password, w)
	if err != nil {
		t.Error(err)
	}

	resp := w.Result()
	if resp.Header.Get("Set-Cookie") == "" {
		t.Error(errors.New("no session cookie"))
	}
}

func TestCurrentUser(t *testing.T) {
	w := httptest.NewRecorder()

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	Config(db, "username")

	user := User{Username: "Erwan", Password: "0000", Mail: "e@e.e"}

	var session Sessionusername
	db.Table("sessionusernames").Where("username = ?", user.Username).First(&session)

	http.SetCookie(w, &http.Cookie{Name: "session-persona", Value: session.Token})
	r := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}

	username, err := GetCurrentUser(r)
	if err != nil {
		t.Error(err)
	}
	if username == "" {
		t.Error("no user loggedin")
	}
}
