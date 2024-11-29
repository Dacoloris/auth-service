package mock

import "fmt"

type MockEmailNotifier struct{}

func (m *MockEmailNotifier) SendWarningEmail(email string, oldIP string, newIP string) error {
	fmt.Printf("Warning: User with email %s has changed IP from %s to %s\n", email, oldIP, newIP)
	return nil
}
