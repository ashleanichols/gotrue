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

type TotpSecret struct {
	ID                 int64     `db:"id"`
	UserID             uuid.UUID `db:"user_id"`
	InstanceID         uuid.UUID `db:"instance_id"`
	EncryptedSecret    []byte    `db:"encrypted_secret"`
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

// NewTotpSecret initializes a new TotpSecret from a userID and secret.
func NewTotpSecret(instanceID, userID uuid.UUID, secret string) (*TotpSecret, error) {
	encryptedSecret := crypto.EncryptSecret([]byte(secret))
	totpSecret := &TotpSecret{
		UserID:          userID,
		InstanceID:      instanceID,
		EncryptedSecret: encryptedSecret,
	}
	return totpSecret, nil
}

func FindTotpSecretByUserId(tx *storage.Connection, userID, instanceID uuid.UUID) (*TotpSecret, error) {
	obj := &TotpSecret{}
	if err := tx.Q().Where("user_id = ? and instance_id = ?", userID, instanceID).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, TotpSecretNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding totp secret")
	}
	return obj, nil
}

func (t *TotpSecret) UpdateOTPLastRequestedAt(tx *storage.Connection) error {
	return tx.UpdateOnly(t, "otp_last_requested_at")
}
