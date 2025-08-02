package shared

import (
	"errors"

	"github.com/google/uuid"
)

func GenerateUUID() string {
	return uuid.New().String()
}

func ParseUUID(id string) (uuid.UUID, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, errors.New("failed to generate UUID")
	}
	return uid, nil
}