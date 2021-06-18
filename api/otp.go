package api

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

type SmsParams struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (a *API) Otp(w http.ResponseWriter, r *http.Request) error {
	switch otpType := r.FormValue("type"); otpType {
	case "sms":
		return a.SmsOtp(w, r)
	case "magiclink":
		return a.MagicLink(w, r)
	default:
		return otpError("unsupported_otp_type", "")
	}
}

// SmsOtp sends the user an otp via sms
func (a *API) SmsOtp(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	instanceID := getInstanceID(ctx)

	params := &SmsParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	if err := jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read sms otp params: %v", err)
	}

	if isValid := a.validateE164Format(params.Phone); !isValid {
		return badRequestError("Invalid format: Phone number should follow the E.164 format")
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
		return internalServerError("Database error finding user").WithInternalError(uerr)
	}

	if err := a.sendPhoneConfirmation(ctx, user, params); err != nil {
		return internalServerError("Error sending confirmation sms").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}

func (a *API) createNewTotpSecret(ctx context.Context, conn *storage.Connection, user *models.User, params *SmsParams) (*models.TotpSecret, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	key, err := crypto.GenerateTotpKey(config, params.Phone)
	if err != nil {
		return nil, internalServerError("error creating totp key").WithInternalError(err)
	}
	totpSecret, err := models.NewTotpSecret(instanceID, user.ID, key.Secret())

	terr := conn.Transaction(func(tx *storage.Connection) error {
		verrs, err := tx.ValidateAndCreate(totpSecret)
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
