# Compare LastPass to iCloud Passwords
This app show the difference between passwords stored in LastPass compared to those stored by Safari.

First export the passwords from each vendor into separate files:
* LastPass has the `Advanced/Export` function
* In Safari, `Settings/Passwords` unlock the store and click on the `...` button at the bottom to export

## Usage
Run with `go run main.go`.

```cmd
Usage of main:
  -o string
        Path to store differences, - is stdout (default stdout)
  -lastp string
        Path to LastPass CSV export file
  -safari string
        Path to Safari passwords CSV export file
```