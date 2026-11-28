package dashboard

import "os"

func readTemplSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}
