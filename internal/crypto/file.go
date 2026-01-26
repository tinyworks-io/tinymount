package crypto

import (
	"os"
)

func writeFileImpl(path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}

func readFileImpl(path string) ([]byte, error) {
	return os.ReadFile(path)
}
