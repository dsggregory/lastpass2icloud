package password

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestSafari(t *testing.T) {
	Convey("Test safari load", t, func() {
		plist, err := LoadSafariPasswords("../../testdata/safari.csv")
		So(err, ShouldBeNil)
		So(len(plist), ShouldEqual, 3)
		So(plist[0].Href, ShouldEqual, "http://one.domain.com")
	})
}

func TestLastpass(t *testing.T) {
	Convey("Test lastpass load", t, func() {
		plist, err := LoadLastpassPasswords("../../testdata/lastpass.csv")
		So(err, ShouldBeNil)
		So(len(plist), ShouldEqual, 4)
		So(plist[0].Href, ShouldEqual, "http://one.domain.com")
	})
}

func TestDiff(t *testing.T) {
	Convey("Test Diff", t, func() {
		conflicts, err := DoDiff("../../testdata/safari.csv", "../../testdata/lastpass.csv")
		So(err, ShouldBeNil)
		for _, p := range conflicts {
			fmt.Print(p.String())
		}
	})
}
