package keychain

import (
	"fmt"
	"github.com/keybase/go-keychain"
)

const AppName = "pass2lastp"

type keychainConfig struct {
	query keychain.Item
}

func NewKeychainConfig() *keychainConfig {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(AppName) // your app name so OS can ask for permission on first attempt
	//query.SetAccessGroup("My Passwords") // what is this?
	query.SetMatchLimit(keychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	return &keychainConfig{query: query}
}

// Query search for a keychain entry matching the webpage of `account`.
func (kc *keychainConfig) Query(account string) ([]keychain.QueryResult, error) {
	kc.query.SetAccount(account)
	kc.query.SetLabel(account)
	results, err := keychain.QueryItem(kc.query)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func testPasswordsGet(account string) {
	kc := NewKeychainConfig()
	results, err := kc.Query(account)
	if err != nil {
		// kc.query.Error(-128) = user-denied
		fmt.Printf("ERROR: %s", err.Error())
	} else if results == nil {
		fmt.Printf("Not found")
	} else {
		for _, r := range results {
			fmt.Printf("%#v\n", r)
		}
	}
}
