package password

import "fmt"

type PassMap map[string]Passwords

func passwordsToMap(passwords Passwords) PassMap {
	m := make(PassMap, len(passwords))
	for _, p := range passwords {
		ep, ok := m[p.Href]
		if !ok {
			m[p.Href] = Passwords{p}
		} else {
			m[p.Href] = append(ep, p)
		}
	}

	return m
}

func (pws Passwords) OLookup(href string) *Password {
	for _, p := range pws {
		if p.Href == href {
			return p
		}
	}
	return nil
}

func DoDiff(safariCSV string, lastpassCSV string) (Passwords, error) {
	safari, err := LoadSafariPasswords(safariCSV)
	if err != nil {
		return nil, err
	}
	safariMap := passwordsToMap(safari)

	lastp, err := LoadLastpassPasswords(lastpassCSV)
	if err != nil {
		return nil, err
	}
	lastpMap := passwordsToMap(lastp)

	conflicts := Passwords{}

	for nm, lpa := range lastpMap {
		lp := lpa[0] // lastpass primary key is url
		if lp.Err != nil {
			conflicts = append(conflicts, lp)
			continue
		}
		spa, ok := safariMap[nm]
		if !ok {
			lp.Err = &PassErr{0, fmt.Errorf("%s; lastpass entry not in safari", lp.Href)}
			conflicts = append(conflicts, lp)
			//lk := safari.OLookup(lp.Href)
			//fmt.Println(lk)
			continue
		}
		// compare user/pass
		found := false
		for _, sp := range spa {
			if sp.User == lp.User && sp.Pass == lp.Pass {
				found = true
				break
			}
		}
		if !found {
			lp.Err = &PassErr{0, fmt.Errorf("u=%s, p=%s; lastpass entry mismatch", lp.User, lp.Pass)}
			conflicts = append(conflicts, lp)
			continue
		}
	}

	return conflicts, nil
}
