package main

import "fmt"

type EmailNotifierMock struct{}

func (m *EmailNotifierMock) SendWarningEmail(email string, oldIP string, newIP string) error {
	fmt.Println("Attention, IP address has changed")
	return nil
}
