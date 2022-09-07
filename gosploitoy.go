package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
)

const (
	ExploitDBaseUrl = "https://exploit-db.com/"
	MaxRetryCount   = 3
)

var wg sync.WaitGroup

func main() {
	workers := flag.Int("t", 5, "Number of workers to utilise.")
	retry := flag.Bool("r", false, "Retry on errors.")

	flag.Parse()

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No cve's detected. Hint: cat cves.txt | gosploitoy")
		os.Exit(1)
	}

	cveExploitResultChan := make(chan string, *workers)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			cveExploitResultChan <- scanner.Text()
		}

		close(cveExploitResultChan)
	}()

	wg.Add(*workers)
	for i := 0; i < *workers; i++ {
		go func() {
			defer wg.Done()

			for cveToSearch := range cveExploitResultChan {
				retryPolicy(func() error {
					return searchExploit(cveToSearch, *retry, cveExploitResultChan)
				})
			}
		}()
	}

	wg.Wait()
}

func searchExploit(cve string, retry bool, cveExploitResultChan chan<- string) error {
	exploitDBRes := struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}{}

	err := makeGetRequest(ExploitDBaseUrl+"search?cve="+cve, &exploitDBRes)
	if err != nil {
		return err
	}

	for _, exploit := range exploitDBRes.Data {
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()

		fmt.Fprintln(w, ExploitDBaseUrl+"exploits/"+exploit.ID)
	}

	return nil
}

func makeGetRequest(url string, target interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header = http.Header{
		"x-requested-with": {"XMLHttpRequest"},
	}

	client := http.DefaultClient

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return errors.New("status code error")
	}

	reqErr := json.NewDecoder(res.Body).Decode(target)
	if reqErr != nil {
		return errors.New("decode error")
	}

	return nil
}

func retryPolicy(callback func() error) {
	for i := 1; i < MaxRetryCount; i++ {
		err := callback()

		if err == nil {
			return
		}
	}
}
