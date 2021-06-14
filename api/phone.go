package api

import "regexp"

const e164Format = `^[1-9]\d{1,14}$`

// Checks if phone number follows the E.164 format
func (a *API) validateE164Format(phone string) bool {
	// match should never fail as long as regexp is valid
	matched, _ := regexp.Match(e164Format, []byte(phone))
	return matched
}
