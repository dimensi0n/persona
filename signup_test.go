package persona

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type User struct {
	gorm.Model        // REQUIRED
	Username   string `gorm:"not null"`        // REQUIRED
	Password   string `gorm:"not null"`        // REQUIRED
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

	db.AutoMigrate(&User{})

	Config(db)

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
