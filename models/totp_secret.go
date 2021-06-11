package models

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage/namespace"
)

type TotpSecret struct {
	ID                 int64     `db:"id"`
	UserID             uuid.UUID `db:"user_id"`
	User               *User     `belongs_to:"user"`
	EncryptedSecret    string    `db:"encrypted_secret"`
	OtpLastRequestedAt time.Time `db:"otp_last_requested_at"`
	CreatedAt          time.Time `db:"created_at"`
	UpdatedAt          time.Time `db:"updated_at"`
}

func (TotpSecret) TableName() string {
	tableName := "totp_secrets"

	if namespace.GetNamespace() != "" {
		return namespace.GetNamespace() + "_" + tableName
	}

	return tableName
}
