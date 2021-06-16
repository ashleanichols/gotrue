package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

const (
	phoneProvider = "phone"
	emailProvider = "email"
)

// SignupParams are the parameters the Signup endpoint accepts
type SignupParams struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password"`
	Phone    string                 `json:"phone"`
	Data     map[string]interface{} `json:"data"`
	Provider string                 `json:"-"`
	Aud      string                 `json:"-"`
}

// Signup is the endpoint for registering a new user
func (a *API) Signup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	cookie := r.Header.Get(useCookieHeader)

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}

	params := &SignupParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read Signup params: %v", err)
	}

	if params.Password == "" {
		return unprocessableEntityError("Signup requires a valid password")
	}
	if len(params.Password) < config.PasswordMinLength {
		return unprocessableEntityError(fmt.Sprintf("Password should be at least %d characters", config.PasswordMinLength))
	}

	if params.Email == "" && params.Phone == "" {
		return unprocessableEntityError("An email address or phone number is required")
	}

	primaryProvider := phoneProvider
	if params.Email != "" {
		if err := a.validateEmail(ctx, params.Email); err != nil {
			return err
		}
		primaryProvider = emailProvider
	}

	if params.Phone != "" {
		if isValid := a.validateE164Format(params.Phone); !isValid {
			return unprocessableEntityError("Invalid phone number format")
		}
		primaryProvider = phoneProvider
	}

	instanceID := getInstanceID(ctx)
	params.Aud = a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(a.db, instanceID, params.Email, params.Aud)
	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user != nil {
			if user.IsConfirmed() {
				return badRequestError("A user with this email address has already been registered")
			}

			if user.IsPhoneConfirmed() {
				return badRequestError("A user with this phone number has already been registered")
			}

			if err := user.UpdateUserMetaData(tx, params.Data); err != nil {
				return internalServerError("Database error updating user").WithInternalError(err)
			}
		} else {
			params.Provider = primaryProvider
			user, terr = a.signupNewUser(ctx, tx, params)
			if terr != nil {
				return terr
			}
		}

		if primaryProvider == emailProvider {
			if config.Mailer.Autoconfirm {
				if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); terr != nil {
					return terr
				}
				if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
					return terr
				}
				if terr = user.Confirm(tx); terr != nil {
					return internalServerError("Database error updating user").WithInternalError(terr)
				}
			} else {
				mailer := a.Mailer(ctx)
				referrer := a.getReferrer(r)
				if terr = sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer); terr != nil {
					return internalServerError("Error sending confirmation mail").WithInternalError(terr)
				}
			}
		} else if primaryProvider == phoneProvider {
			if config.Sms.Autoconfirm {
				if terr = user.ConfirmPhone(tx); terr != nil {
					return internalServerError("Database error updating user").WithInternalError(terr)
				}
			} else {
				var otp string
				var secret string
				totp, terr := models.FindTotpSecretByUserId(a.db, user.ID, instanceID)
				smsParams := &SmsParams{
					Email: params.Email,
					Phone: params.Phone,
				}
				if terr != nil {
					if models.IsNotFoundError(terr) {
						totp, err = a.createNewTOTPSecret(ctx, a.db, user, smsParams)
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
					// need to consider case of an unconfirmed existing user and resend otp
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

				smsProvider, err := sms_provider.GetSmsProvider(*config)
				if err != nil {
					return err
				}

				if serr := smsProvider.SendSms(smsParams.Phone, otp); serr != nil {
					return serr
				}
			}
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every minute")
		}
		return err
	}

	// handles case where Mailer.Autoconfirm is true or Phone.Autoconfirm is true
	if user.IsConfirmed() || user.IsPhoneConfirmed() {
		var token *AccessTokenResponse
		err = a.db.Transaction(func(tx *storage.Connection) error {
			var terr error
			if terr = models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, nil); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
				return terr
			}

			token, terr = a.issueRefreshToken(ctx, tx, user)
			if terr != nil {
				return terr
			}

			if cookie != "" && config.Cookie.Duration > 0 {
				if terr = a.setCookieToken(config, token.Token, cookie == useSessionCookie, w); terr != nil {
					return internalServerError("Failed to set JWT cookie. %s", terr)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		metering.RecordLogin("password", user.ID, instanceID)
		token.User = user
		return sendJSON(w, http.StatusOK, token)
	}

	return sendJSON(w, http.StatusOK, user)
}

func (a *API) signupNewUser(ctx context.Context, conn *storage.Connection, params *SignupParams) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	user, err := models.NewUser(instanceID, params.Email, params.Password, params.Aud, params.Data)
	if err != nil {
		return nil, internalServerError("Database error creating user").WithInternalError(err)
	}
	if user.AppMetaData == nil {
		user.AppMetaData = make(map[string]interface{})
	}
	user.AppMetaData["provider"] = params.Provider

	if params.Password == "" {
		user.EncryptedPassword = ""
	}

	if params.Phone != "" {
		user.Phone = params.Phone
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(user); terr != nil {
			return internalServerError("Database error saving new user").WithInternalError(terr)
		}
		if terr := user.SetRole(tx, config.JWT.DefaultGroupName); terr != nil {
			return internalServerError("Database error updating user").WithInternalError(terr)
		}
		if terr := triggerEventHooks(ctx, tx, ValidateEvent, user, instanceID, config); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}
