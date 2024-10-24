package whatsapp

import (
	"errors"

	"github.com/authgear/authgear-server/pkg/api/event"
	"github.com/authgear/authgear-server/pkg/api/event/nonblocking"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/log"
	"github.com/authgear/authgear-server/pkg/util/secretcode"
)

type Logger struct{ *log.Logger }

func NewLogger(lf *log.Factory) Logger { return Logger{lf.New("whatsapp")} }

type EventService interface {
	DispatchEvent(payload event.Payload) error
}

type Provider struct {
	CodeStore       *StoreRedis
	Clock           clock.Clock
	Logger          Logger
	WATICredentials *config.WATICredentials
	Events          EventService
}

func (p *Provider) GetServerWhatsappPhone() string {
	// return the phone from different config when more whatsapp api provider is supported
	if p.WATICredentials != nil {
		return p.WATICredentials.WhatsappPhoneNumber
	}
	return ""
}

func (p *Provider) GetCode(phone string) (*Code, error) {
	return p.CodeStore.Get(phone)
}

func (p *Provider) CreateCode(phone string, appID string, webSessionID string) (*Code, error) {
	code := secretcode.OOBOTPSecretCode.Generate()
	codeModel := &Code{
		AppID:        appID,
		WebSessionID: webSessionID,
		Phone:        phone,
		Code:         code,
		ExpireAt:     p.Clock.NowUTC().Add(WhatsappCodeDuration),
	}

	err := p.CodeStore.Create(codeModel)
	if err != nil {
		return nil, err
	}
	return codeModel, nil
}

func (p *Provider) VerifyCode(phone string, webSessionID string, consume bool) (*Code, error) {
	codeModel, err := p.CodeStore.Get(phone)
	if errors.Is(err, ErrCodeNotFound) {
		return nil, ErrInvalidCode
	} else if err != nil {
		return nil, err
	}

	if webSessionID != codeModel.WebSessionID {
		return nil, ErrWebSessionIDMismatch
	}

	if codeModel.UserInputtedCode == "" {
		return nil, ErrInputRequired
	}

	if !secretcode.OOBOTPSecretCode.Compare(codeModel.UserInputtedCode, codeModel.Code) {
		return nil, ErrInvalidCode
	}

	if consume {
		if err := p.CodeStore.Delete(phone); err != nil {
			p.Logger.WithError(err).Error("whatsapp: failed to delete code")
		}
		if err := p.Events.DispatchEvent(&nonblocking.WhatsappOTPVerifiedEventPayload{
			Phone: phone,
		}); err != nil {
			return nil, err
		}
	}

	return codeModel, nil
}

func (p *Provider) SetUserInputtedCode(phone string, userInputtedCode string) (*Code, error) {
	codeModel, err := p.CodeStore.Get(phone)
	if err != nil {
		return nil, err
	}

	codeModel.UserInputtedCode = userInputtedCode
	if err := p.CodeStore.Update(codeModel); err != nil {
		return nil, err
	}

	return codeModel, nil
}
