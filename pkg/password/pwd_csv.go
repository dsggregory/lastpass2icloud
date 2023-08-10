package password

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

type Passwords []*Password

type PassErr struct {
	LineNum int
	Err     error
}

func (e *PassErr) Error() string {
	if e.LineNum > 0 {
		return fmt.Sprintf("%s; at line number %d", e.Err.Error(), e.LineNum)
	} else {
		return e.Err.Error()
	}
}

func (e *PassErr) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Error())
}

type Password struct {
	Href    string
	User    string
	Pass    string
	Comment string
	DateRef time.Time
	Err     *PassErr
}

type ToPassFunc func(rec []string, password *Password)

func (p *Password) String() string {
	buf := strings.Builder{}
	enc := json.NewEncoder(&buf)
	_ = enc.Encode(p)

	return buf.String()
}

func LoadPasswords(path string, toPassword ToPassFunc) (Passwords, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	r := csv.NewReader(fp)
	_, _ = r.Read() // skip header

	plist := Passwords{}

	lineno := 0
	for {
		lineno++
		p := Password{}
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			p.Err = &PassErr{LineNum: lineno, Err: err}
			plist = append(plist, &p)
			continue
		}
		// CSV Read will fail if not enough fields in input so we don't risk an ABR
		toPassword(rec, &p)
		plist = append(plist, &p)
	}

	return plist, nil
}

// LoadSafariPasswords
// Title,URL,Username,Password,Notes,OTPAuth
func LoadSafariPasswords(path string) (Passwords, error) {
	plist, err := LoadPasswords(path, func(rec []string, p *Password) {
		p.Href = rec[1]
		p.User = rec[2]
		p.Pass = rec[3]
		p.Comment = rec[4]
	})

	return plist, err
}

// LoadLastpassPasswords
// url,username,password,extra,name,grouping,fav
func LoadLastpassPasswords(path string) (Passwords, error) {
	plist, err := LoadPasswords(path, func(rec []string, p *Password) {
		u, err := url.Parse(rec[0])
		if err != nil {
			p.Href = rec[0]
		} else {
			p.Href = fmt.Sprintf("%s://%s/", u.Scheme, u.Host)
			if len(u.Path) > 1 {
				fmt.Println(u.Path)
			}
		}
		p.User = rec[1]
		p.Pass = rec[2]
		p.Comment = rec[3]
	})

	return plist, err
}
