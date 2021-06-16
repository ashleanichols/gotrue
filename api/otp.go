package api

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

type SmsParams struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (a *API) OTP(w http.ResponseWriter, r *http.Request) error {
	switch otpType := r.FormValue("type"); otpType {
	case "sms":
		return a.SendSmsOTP(w, r)
	case "magiclink":
		return a.MagicLink(w, r)
	default:
		return otpError("unsupported_otp_type", "")
	}
}

// SendSmsOTP sends the user an OTP
func (a *API) SendSmsOTP(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	params := &SmsParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	if err := jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read sms otp params: %v", err)
	}

	if isValid := a.validateE164Format(params.Phone); !isValid {
		return badRequestError("Invalid format: Phone number should follow the E.164 format")
	}

	smsProvider, err := sms_provider.GetSmsProvider(*config)
	if err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)

	user, uerr := models.FindUserByPhoneAndAudience(a.db, instanceID, params.Phone, aud)
	if uerr != nil {
		// if user does not exists, sign up the user
		if models.IsNotFoundError(uerr) {
			password, err := password.Generate(64, 10, 0, false, true)
			if err != nil {
				internalServerError("error creating user").WithInternalError(err)
			}
			newBodyContent := `{"email":"` + params.Email + `","phone":"` + params.Phone + `","password":"` + password + `"}`
			r.Body = ioutil.NopCloser(strings.NewReader(newBodyContent))
			r.ContentLength = int64(len(newBodyContent))

			fakeResponse := &responseStub{}

			if err := a.Signup(fakeResponse, r); err != nil {
				return err
			}
			return sendJSON(w, http.StatusOK, make(map[string]string))
		}
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	var otp string
	var secret string

	totp, terr := models.FindTotpSecretByUserId(a.db, user.ID, instanceID)
	if terr != nil {
		if models.IsNotFoundError(terr) {
			totp, err = a.createNewTOTPSecret(ctx, a.db, user, params)
			if err != nil {
				return err
			}
			secret, err = crypto.DecryptSecret(totp.EncryptedSecret)
			if err != nil {
				return internalServerError("error decrypting secret").WithInternalError(err)
			}
		} else {
			return internalServerError("error retrieving secret").WithInternalError(err)
		}
	} else {
		secret, err = crypto.DecryptSecret(totp.EncryptedSecret)
		if err != nil {
			return internalServerError("error decrypting secret").WithInternalError(err)
		}
	}
	totp.OtpLastRequestedAt = time.Now()
	otp, err = crypto.GenerateTOTP(secret, totp.OtpLastRequestedAt, 30)
	if err != nil {
		return internalServerError("error generating sms otp").WithInternalError(err)
	}

	if err := totp.UpdateOTPLastRequestedAt(a.db); err != nil {
		return internalServerError("error updating otp_last_requested_at").WithInternalError(err)
	}

	if !config.Sms.Autoconfirm {
		if serr := smsProvider.SendSms(params.Phone, otp); serr != nil {
			return serr
		}
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}

func (a *API) createNewTOTPSecret(ctx context.Context, conn *storage.Connection, user *models.User, params *SmsParams) (*models.TotpSecret, error) {
	instanceID := getInstanceID(ctx)

	key, err := crypto.GenerateTOTPKey(params.Phone)
	if err != nil {
		return nil, internalServerError("error creating totp key").WithInternalError(err)
	}
	totpSecret, err := models.NewTotpSecret(instanceID, user.ID, key.Secret())

	terr := conn.Transaction(func(tx *storage.Connection) error {
		verrs, err := tx.ValidateAndSave(totpSecret)
		if verrs.Count() > 0 {
			return internalServerError("Database error saving new totp secret").WithInternalError(verrs)
		}
		if err != nil {
			return internalServerError("Database error saving new totp secret").WithInternalError(err)
		}
		return nil
	})
	if terr != nil {
		return nil, terr
	}
	return totpSecret, nil
}
