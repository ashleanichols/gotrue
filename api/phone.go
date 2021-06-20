package api

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
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

func (a *API) sendPhoneConfirmation(ctx context.Context, user *models.User, phone string) error {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	totp, err := models.FindTotpSecretByUserId(a.db, user.ID, instanceID)

	if totp != nil && totp.OtpLastRequestedAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	var otp string
	var secret string
	if err != nil {
		if models.IsNotFoundError(err) {
			totp, err = a.createNewTotpSecret(ctx, a.db, user, phone)
			if err != nil {
				return err
			}
		} else {
			return internalServerError("error retrieving secret").WithInternalError(err)
		}
	}
	secret, err = crypto.DecryptSecret(totp.EncryptedSecret)
	if err != nil {
		return internalServerError("error decrypting secret").WithInternalError(err)
	}

	now := time.Now()
	totp.OtpLastRequestedAt = &now
	otp, err = crypto.GenerateOtp(secret, totp.OtpLastRequestedAt, config.Sms.OtpExp)
	if err != nil {
		return internalServerError("error generating sms otp").WithInternalError(err)
	}

	if err := totp.UpdateOtpLastRequestedAt(a.db); err != nil {
		return internalServerError("error updating otp_last_requested_at").WithInternalError(err)
	}

	smsProvider, err := sms_provider.GetSmsProvider(*config)
	if err != nil {
		return err
	}

	if serr := smsProvider.SendSms(phone, otp); serr != nil {
		return serr
	}

	return nil
}
