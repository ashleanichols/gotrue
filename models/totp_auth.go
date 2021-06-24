package models

import (
	"database/sql"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/namespace"
	"github.com/pkg/errors"
)

type TotpAuth struct {
	ID                 int64      `db:"id"`
	UserID             uuid.UUID  `db:"user_id"`
	InstanceID         uuid.UUID  `db:"instance_id"`
	EncryptedUrl       []byte     `db:"encrypted_url"`
	OtpLastRequestedAt *time.Time `db:"otp_last_requested_at"`
	CreatedAt          time.Time  `db:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at"`
}

func (TotpAuth) TableName() string {
	tableName := "totp_auth"

	if namespace.GetNamespace() != "" {
		return namespace.GetNamespace() + "_" + tableName
	}

	return tableName
}

// NewTotpAuth initializes a new TotpAuth from a userID and url containing the secret.
func NewTotpAuth(instanceID, userID uuid.UUID, url string) (*TotpAuth, error) {
	encryptedUrl, err := crypto.EncryptTotpUrl([]byte(url))
	if err != nil {
		return nil, err
	}
	totpAuth := &TotpAuth{
		UserID:             userID,
		InstanceID:         instanceID,
		EncryptedUrl:       encryptedUrl,
		OtpLastRequestedAt: nil,
	}
	return totpAuth, nil
}

func FindTotpAuthByUserId(tx *storage.Connection, userID, instanceID uuid.UUID) (*TotpAuth, error) {
	obj := &TotpAuth{}
	if err := tx.Q().Where("user_id = ? and instance_id = ?", userID, instanceID).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, TotpSecretNotFoundError{}
		}
		return nil, errors.Wrap(err, "error retrieving totp auth data")
	}
	return obj, nil
}

func (t *TotpAuth) UpdateOtpLastRequestedAt(tx *storage.Connection) error {
	return tx.UpdateOnly(t, "otp_last_requested_at")
}
