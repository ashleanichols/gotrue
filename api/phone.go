package api

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

const e164Format = `^[1-9]\d{1,14}$`

// validateE165Format checks if phone number follows the E.164 format
func (a *API) validateE164Format(phone string) bool {
	// match should never fail as long as regexp is valid
	matched, _ := regexp.Match(e164Format, []byte(phone))
	return matched
}

// formatPhoneNumber removes "+" and whitespaces in a phone number
func (a *API) formatPhoneNumber(phone string) string {
	return strings.ReplaceAll(strings.Trim(phone, "+"), " ", "")
}

func (a *API) sendPhoneConfirmation(tx *storage.Connection, ctx context.Context, user *models.User, phone string) error {
	config := a.getConfig(ctx)

	if user.ConfirmationSentAt != nil && !user.ConfirmationSentAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	// use totp key to generate 6 digit otp
	key, err := crypto.GenerateTotpKey(config, phone)
	if err != nil {
		return internalServerError("error creating totp key").WithInternalError(err)
	}

	now := time.Now()
	oldToken := user.ConfirmationToken
	user.ConfirmationToken, err = crypto.GenerateOtp(key.Secret(), &now, config.Sms.OtpExp)
	if err != nil {
		user.ConfirmationToken = oldToken
		return internalServerError("error generating sms otp").WithInternalError(err)
	}

	smsProvider, err := sms_provider.GetSmsProvider(*config)
	if err != nil {
		return err
	}

	if serr := smsProvider.SendSms(phone, user.ConfirmationToken); serr != nil {
		user.ConfirmationToken = oldToken
		return serr
	}

	user.ConfirmationSentAt = &now

	return errors.Wrap(tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at"), "Database error updating user for confirmation")
}

func (a *API) sendPhoneChange(tx *storage.Connection, ctx context.Context, user *models.User, phone string) error {
	config := a.getConfig(ctx)

	if user.PhoneChangeSentAt != nil && !user.PhoneChangeSentAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	key, err := crypto.GenerateTotpKey(config, phone)
	if err != nil {
		return internalServerError("error creating totp key").WithInternalError(err)
	}

	now := time.Now()
	oldToken := user.PhoneChangeToken
	user.PhoneChangeToken, err = crypto.GenerateOtp(key.Secret(), &now, config.Sms.OtpExp)
	if err != nil {
		user.PhoneChangeToken = oldToken
		return internalServerError("error generating sms otp").WithInternalError(err)
	}

	smsProvider, err := sms_provider.GetSmsProvider(*config)
	if err != nil {
		return err
	}

	if serr := smsProvider.SendSms(phone, user.PhoneChangeToken); serr != nil {
		user.PhoneChangeToken = oldToken
		return serr
	}
	user.PhoneChange = phone
	user.PhoneChangeSentAt = &now

	return errors.Wrap(tx.UpdateOnly(user, "phone_change", "phone_change_token", "phone_change_sent_at"), "Database error updating user for phone update")
}
