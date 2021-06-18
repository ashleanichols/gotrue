package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
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

	primaryProvider := "phone"
	if params.Email != "" {
		if err := a.validateEmail(ctx, params.Email); err != nil {
			return err
		}
		primaryProvider = "email"
	}

	if params.Phone != "" {
		if isValid := a.validateE164Format(params.Phone); !isValid {
			return unprocessableEntityError("Invalid phone number format")
		}
		primaryProvider = "phone"
	}

	instanceID := getInstanceID(ctx)
	params.Aud = a.requestAud(ctx, r)
	user, uerr := models.FindUserByEmailOrPhone(a.db, instanceID, params.Email, params.Phone, params.Aud)
	if uerr != nil && !models.IsNotFoundError(uerr) {
		return internalServerError("Database error finding user").WithInternalError(uerr)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user != nil {
			if user.IsConfirmed() || user.IsPhoneConfirmed() {
				return badRequestError("A user with this email address or phone number has already been registered")
			}

			if user.GetEmail() == "" {
				if err := user.SetEmail(tx, params.Email); err != nil {
					return badRequestError("Database error updating user").WithInternalError(err)
				}
			} else if user.GetEmail() != params.Email {
				return badRequestError("This email address has been taken")
			}

			if user.GetPhone() == "" {
				if err := user.SetPhone(tx, params.Phone); err != nil {
					return badRequestError("Database error updating user").WithInternalError(err)
				}
			} else if user.GetPhone() != params.Phone {
				return badRequestError("This phone number has been taken")
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

		if user.GetEmail() != "" && !user.IsConfirmed() {
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
		}

		if user.GetPhone() != "" && !user.IsPhoneConfirmed() {
			if config.Sms.Autoconfirm {
				if terr = user.ConfirmPhone(tx); terr != nil {
					return internalServerError("Database error updating user").WithInternalError(terr)
				}
			} else {
				smsParams := &SmsParams{
					Email: user.GetEmail(),
					Phone: user.GetPhone(),
				}
				if terr = a.sendPhoneConfirmation(ctx, user, smsParams); terr != nil {
					return internalServerError("Error sending confirmation sms").WithInternalError(terr)
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
		user.Phone = storage.NullString(params.Phone)
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
