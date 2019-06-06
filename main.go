package main

import (
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	uuid "github.com/satori/go.uuid"
)

type user struct {
	Firstname string
	Lastname  string
	Email     string
	UserName  string
	Password  []byte
}

var tpl *template.Template
var dbUsers = map[string]user{}
var dbSessions = map[string]string{}

func main() {

}

func SignUp(w http.ResponseWriter, req *http.Request) {
	if alreadyLogin(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	// form submission
	if req.Method == http.MethodPost {

		f := req.FormValue("firstname")
		l := req.FormValue("lastname")
		e := req.FormValue("email")
		un := req.FormValue("username")
		p := req.FormValue("password")

		// username availability
		if _, ok := dbUsers[un]; ok {
			http.Error(w, "username already taken", http.StatusForbidden)
			return
		}

		// encrypt password
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// cookie session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		un = dbSessions[c.Value]

		// store the user
		u := user{f, l, e, un, bs}
		dbUsers[un] = u

		// redirect
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}


}
