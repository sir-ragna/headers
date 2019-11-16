package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func ciHeaderCheck(expected, header, message string) {
	if strings.EqualFold(expected, header) {
		fmt.Println(message)
	}
}

type HeaderComment struct {
	exists  bool
	name    string
	value   string
	comment string
	weight  int
}

func scan(url string) {
	if !strings.EqualFold("http://", url[:7]) &&
		!strings.EqualFold("https://", url[:8]) {
		url = "https://" + url
	}

	fmt.Printf("[%s]%s\r\n", url, strings.Repeat("-", 78-len(url)))
	res, err := http.Head(url)
	// Do a Head for now.
	// We need a full GET to check for SRI later as well.

	if err != nil {
		// handle error
		fmt.Println(err)
		return
	}

	var headerComments []HeaderComment
	headerComments = append(headerComments, HeaderComment{
		false,
		"X-Frame-Options",
		"",
		"The X-Frame-Options helps prevent ClickJacking attacks.",
		20,
	})
	headerComments = append(headerComments, HeaderComment{
		false,
		"X-Powered-By",
		"",
		"The X-Powered-By gives an attacker information.",
		-20,
	})
	headerComments = append(headerComments, HeaderComment{
		false,
		"X-Content-Type-Options",
		"",
		"The X-Content-Type-Options: nosniff prevents browsers from infering " +
			"the datatype of content.",
		10,
	})
	headerComments = append(headerComments, HeaderComment{
		false,
		"Content-Type",
		"",
		"Always a good idea to set the Content-Type.",
		10,
	})
	headerComments = append(headerComments, HeaderComment{
		false,
		"Content-Security-Policy",
		"",
		"CSP is the future of HTTP security headers. This tool doens't check " +
			"whether you have a good policy though. Manual review required.",
		30,
	})
	headerComments = append(headerComments, HeaderComment{
		false,
		"Public-Key-Pins",
		"",
		"HTTP Public Key Pinning can lock your users out. The risks of using " +
			"HPKP sometimes outweigh the benefits.",
		0,
	})
	headerComments = append(headerComments, HeaderComment{
		false,
		"Strict-Transport-Security",
		"",
		"HSTS enforces HTTPS after the first visit. " +
			"This prevents MiTM attacks.",
		10,
	})

	for resHeadName, resHeadValues := range res.Header {
		if len(resHeadValues) != 1 {
			fmt.Println("Duplicate headers: ", resHeadName)
			for val := range resHeadValues {
				fmt.Println("\t:: ", val)
			}
			return
		}

		if strings.EqualFold("Set-Cookie", resHeadName) {
			if strings.Contains(strings.ToLower(resHeadValues[0]), "secure") {
				headerComments = append(headerComments, HeaderComment{
					true,
					"Cookie 'Secure'",
					resHeadValues[0],
					"The 'Secure' flag makes sure that the cookies are only " +
						"send over HTTPS",
					15,
				})
			} else {
				headerComments = append(headerComments, HeaderComment{
					true,
					"Cookie 'Secure'",
					resHeadValues[0],
					"The 'Secure' flag makes sure that the cookies are only " +
						"send over HTTPS",
					-10,
				})
			}
			if strings.Contains(strings.ToLower(resHeadValues[0]), "httponly") {
				headerComments = append(headerComments, HeaderComment{
					true,
					"Cookie 'HttpOnly'",
					resHeadValues[0],
					"The 'HttpOnly' flag makes sure the cookie can not be " +
						"read out in Javascript.",
					10,
				})
			} else {
				headerComments = append(headerComments, HeaderComment{
					true,
					"Cookie 'HttpOnly'",
					resHeadValues[0],
					"The 'HttpOnly' flag makes sure the cookie can not be " +
						"read out in Javascript.",
					-10,
				})
			}
		}

		for index, headerComment := range headerComments {
			if strings.EqualFold(headerComment.name, resHeadName) {
				headerComments[index].exists = true
				headerComments[index].value = resHeadValues[0]
			}
		}
	}

	var score = 0
	for _, header := range headerComments {
		if header.exists && header.weight >= 0 {
			fmt.Printf("[+%d] Header: %s\r\n\t%s\r\n", header.weight, header.name, header.comment)
			score += header.weight
		} else if header.exists && header.weight < 0 {
			fmt.Printf("[%d] Header %s\r\n\t%s\r\n", header.weight, header.name,
				header.comment)
			score += header.weight
		} else if !header.exists && header.weight > 0 {
			fmt.Printf("[   ] Missing header: (%d) %s\r\n\t%s\r\n", header.weight, header.name, header.comment)
		}
	}
	fmt.Println("Final score: ", score)
}

func main() {
	args := os.Args[1:]
	for _, url := range args {
		scan(url)
	}
	if len(args) == 0 {
		fmt.Printf("Usage: %s [[url] url...]\r\n", os.Args[0])
	}
}
