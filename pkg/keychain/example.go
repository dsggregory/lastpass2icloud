package keychain

import (
	"fmt"
	"github.com/keybase/go-keychain"
	"os"
)

func testPasswordsGet() {
	account := os.Args[1]

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("Passwords") // is this right?
	query.SetAccount(account)
	query.SetAccessGroup("accessGroup") // what is this?
	query.SetMatchLimit(keychain.MatchLimitAll)
	query.SetReturnAttributes(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		fmt.Printf("ERROR: %s", err.Error())
	} else if results == nil {
		fmt.Printf("Not found")
	} else {
		for _, r := range results {
			fmt.Printf("%#v\n", r)
		}
	}
}
