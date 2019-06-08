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

	http.HandleFunc("/", SignUp)
	http.HandleFunc("/login", login)
	http.HandleFunc("/userPage", userPage)
	http.Handle("/images/", http.FileServer(http.Dir("public")))
	http.Handle("/demo-images/", http.FileServer(http.Dir("public")))
	http.Handle("/js/", http.FileServer(http.Dir("public")))
	http.Handle("/fonts/", http.FileServer(http.Dir("public")))
	http.ListenAndServe(":8080", nil)

}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func userPage(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	if !alreadyLogin(req) {
		http.Error(w, "You are not logged in", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "index.html", u)
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
		http.Redirect(w, req, "/userPage", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "signup.html", nil)

}

func login(w http.ResponseWriter, req *http.Request) {
	if alreadyLogin(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	// form values
	if req.Method == http.MethodPost {
		// get values
		un := req.FormValue("username")
		p := req.FormValue("password")

		// username availabilty
		u, ok := dbUsers[un]
		if !ok {
			http.Error(w, "username not available", http.StatusForbidden)
			return
		}

		// match username to password
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
			http.Error(w, "username and password dont match", http.StatusForbidden)
			return
		}

		// cookie session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		dbSessions[c.Value] = un

		// redirect
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "login.html", nil)

}
