package lib

import (
	"fmt"
	"io"
	"net/http"
)

func GetRemoteURLContent(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get remote content -> %s: %s", url, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func GetRemoteURLReader(url string) (io.ReadCloser, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get remote content -> %s: %s", url, resp.Status)
	}

	return resp.Body, nil
}
