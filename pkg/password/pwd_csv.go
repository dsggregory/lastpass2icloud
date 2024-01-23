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
	Offset int64
	Err    error
}

func (e *PassErr) Error() string {
	if e.Offset > 0 {
		return fmt.Sprintf("%s; at offset %d", e.Err.Error(), e.Offset)
	} else {
		return e.Err.Error()
	}
}

func (e *PassErr) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Error())
}

const (
	SrcSafari = "safari"
	SrcLastp  = "lastp"
)

type PwSrc struct {
	Source string
	Offset int64
}

type Password struct {
	// BaseHref simplified URL from input to match safari to lastpass
	BaseHref string
	// OrigHref unaltered URL from input file
	OrigHref string
	User     string
	Pass     string
	Comment  string
	DateRef  time.Time
	Err      *PassErr
	PwSrc
}

type ToPassFunc func(rec []string, password *Password)

// ToJSON convert password to json
func (p *Password) ToJSON() string {
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

	var offset int64
	for {
		offset = r.InputOffset()
		p := Password{}
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			p.Err = &PassErr{Offset: offset, Err: err}
			plist = append(plist, &p)
			continue
		}
		// CSV Read will fail if not enough fields in input so we don't risk an ABR
		toPassword(rec, &p)
		p.PwSrc.Offset = offset
		plist = append(plist, &p)
	}

	return plist, nil
}

// LoadSafariPasswords
// Title,URL,Username,Password,Notes,OTPAuth
func LoadSafariPasswords(path string) (Passwords, error) {
	plist, err := LoadPasswords(path, func(rec []string, p *Password) {
		p.BaseHref = rec[1]
		p.OrigHref = p.BaseHref
		p.User = rec[2]
		p.Pass = rec[3]
		p.Comment = rec[4]
		p.PwSrc.Source = SrcSafari
	})

	return plist, err
}

// LoadLastpassPasswords
// url,username,password,extra,name,grouping,fav
func LoadLastpassPasswords(path string) (Passwords, error) {
	plist, err := LoadPasswords(path, func(rec []string, p *Password) {
		u, err := url.Parse(rec[0])
		if err != nil {
			p.BaseHref = rec[0]
		} else {
			p.BaseHref = fmt.Sprintf("%s://%s/", u.Scheme, u.Host)
		}
		p.OrigHref = rec[0]
		p.User = rec[1]
		p.Pass = rec[2]
		p.Comment = rec[3]
		p.PwSrc.Source = SrcLastp
	})

	return plist, err
}

// ExportSafariPasswords export list of passwords to Safari format for possible import
func ExportSafariPasswords(pws Passwords, fp *os.File) error {
	_, _ = fp.WriteString("Title,URL,Username,Password,Notes,OTPAuth\n")
	w := csv.NewWriter(fp)

	for _, p := range pws {
		title := ""
		href, err := url.Parse(p.BaseHref)
		if err != nil {
			return err
		}
		title = fmt.Sprintf("%s (%s)", href.Host, p.User)
		if err := w.Write([]string{title, p.OrigHref, p.User, p.Pass, p.Comment, ""}); err != nil {
			return err
		}
	}

	return nil
}
