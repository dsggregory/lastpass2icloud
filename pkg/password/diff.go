package password

import (
	"fmt"
	"sort"
	"strings"
)

type PassMap map[string]Passwords

func passwordsToMap(passwords Passwords) PassMap {
	m := make(PassMap, len(passwords))
	for _, p := range passwords {
		ep, ok := m[p.BaseHref]
		if !ok {
			m[p.BaseHref] = Passwords{p}
		} else {
			m[p.BaseHref] = append(ep, p)
		}
	}

	return m
}

func (pws Passwords) OLookup(href string) *Password {
	for _, p := range pws {
		if p.BaseHref == href {
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
			lp.Err = &PassErr{0, fmt.Errorf("%s; lastpass entry not in safari", lp.BaseHref)}
			conflicts = append(conflicts, lp)
			//lk := safari.OLookup(lp.BaseHref)
			//fmt.Println(lk)
			continue
		}
		// compare user/pass
		found := false
		screds := []string{}
		for _, sp := range spa {
			if sp.User == lp.User && sp.Pass == lp.Pass {
				found = true
				break
			}
			screds = append(screds, sp.User+"/"+sp.Pass+":"+fmt.Sprintf("%d", sp.PwSrc.Offset))
		}
		if !found {
			lp.Err = &PassErr{0, fmt.Errorf("screds=%v; lastpass entry mismatch", screds)}
			conflicts = append(conflicts, lp)
			continue
		}
	}

	sort.Slice(conflicts, func(i, j int) bool {
		x := strings.Compare(conflicts[i].OrigHref, conflicts[j].OrigHref)
		if x < 0 {
			return true
		}
		return false
	})

	return conflicts, nil
}
