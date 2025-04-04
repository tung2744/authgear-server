package nodes

import (
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/interaction"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	interaction.RegisterNode(&NodeCreateAuthenticatorWhatsappOTPSetup{})
}

type InputCreateAuthenticatorWhatsappOTPSetup interface {
	GetWhatsappPhone() string
}

type EdgeCreateAuthenticatorWhatsappOTPSetup struct {
	NewAuthenticatorID string
	Stage              authn.AuthenticationStage
	IsDefault          bool
}

type InputCreateAuthenticatorWhatsappOTPSetupSelect interface {
	SetupPrimaryAuthenticatorWhatsappOTP()
}

func (e *EdgeCreateAuthenticatorWhatsappOTPSetup) IsDefaultAuthenticator() bool {
	return false
}

func (e *EdgeCreateAuthenticatorWhatsappOTPSetup) AuthenticatorType() model.AuthenticatorType {
	return model.AuthenticatorTypeOOBSMS
}

func (e *EdgeCreateAuthenticatorWhatsappOTPSetup) Instantiate(ctx *interaction.Context, graph *interaction.Graph, rawInput interface{}) (interaction.Node, error) {
	var userID string
	var phone string
	if e.Stage == authn.AuthenticationStagePrimary {
		var input InputCreateAuthenticatorWhatsappOTPSetupSelect
		matchedInput := interaction.Input(rawInput, &input)
		if !matchedInput && !interaction.IsAdminAPI(rawInput) {
			return nil, interaction.ErrIncompatibleInput
		}
		identityInfo := graph.MustGetUserLastIdentity()
		userID = identityInfo.UserID
		phone = identityInfo.LoginID.LoginID
	} else {
		var input InputCreateAuthenticatorWhatsappOTPSetup
		if !interaction.Input(rawInput, &input) {
			return nil, interaction.ErrIncompatibleInput
		}
		userID = graph.MustGetUserID()
		phone = input.GetWhatsappPhone()
	}

	err := validation.FormatPhone{}.CheckFormat(phone)
	if err != nil {
		validationCtx := &validation.Context{}
		validationCtx.EmitError("format", map[string]interface{}{"format": "phone"})
		return nil, validationCtx.Error("invalid target")
	}
	phone, err = ctx.LoginIDNormalizerFactory.NormalizerWithLoginIDType(model.LoginIDKeyTypePhone).
		Normalize(phone)
	if err != nil {
		return nil, err
	}

	spec := &authenticator.Spec{
		UserID:    userID,
		IsDefault: e.IsDefault,
		Kind:      stageToAuthenticatorKind(e.Stage),
		Type:      e.AuthenticatorType(),
		OOBOTP: &authenticator.OOBOTPSpec{
			Phone: phone,
		},
	}

	info, err := ctx.Authenticators.NewWithAuthenticatorID(e.NewAuthenticatorID, spec)
	if err != nil {
		return nil, err
	}

	var skipInput interface{ SkipVerification() bool }
	if interaction.Input(rawInput, &skipInput) && skipInput.SkipVerification() {
		// Admin skip verify whatsapp otp and create OOB authenticator directly
		return &NodeCreateAuthenticatorOOB{Stage: e.Stage, Authenticator: info}, nil
	}

	// Skip checking whatsapp otp if the phone number is verified
	// Create OOB authenticator directly
	aStatus, err := ctx.Verification.GetAuthenticatorVerificationStatus(info)
	if err != nil {
		return nil, err
	}
	if aStatus == verification.AuthenticatorStatusVerified {
		return &NodeCreateAuthenticatorOOB{Stage: e.Stage, Authenticator: info}, nil
	}

	code, err := ctx.WhatsappCodeProvider.CreateCode(phone, string(ctx.Config.ID), ctx.WebSessionID)
	if err != nil {
		return nil, err
	}

	return &NodeCreateAuthenticatorWhatsappOTPSetup{
		Stage:         e.Stage,
		Authenticator: info,
		WhatsappOTP:   code.Code,
		Phone:         phone,
		PhoneOTPMode:  ctx.Config.Authenticator.OOB.SMS.PhoneOTPMode,
	}, nil
}

type NodeCreateAuthenticatorWhatsappOTPSetup struct {
	Stage         authn.AuthenticationStage        `json:"stage"`
	Authenticator *authenticator.Info              `json:"authenticator"`
	WhatsappOTP   string                           `json:"whatsapp_otp"`
	Phone         string                           `json:"phone"`
	PhoneOTPMode  config.AuthenticatorPhoneOTPMode `json:"phone_otp_mode"`
}

// GetPhoneOTPMode implements WhatsappOTPNode.
func (n *NodeCreateAuthenticatorWhatsappOTPSetup) GetPhoneOTPMode() config.AuthenticatorPhoneOTPMode {
	return n.PhoneOTPMode
}

// GetWhatsappOTP implements WhatsappOTPNode.
func (n *NodeCreateAuthenticatorWhatsappOTPSetup) GetWhatsappOTP() string {
	return n.WhatsappOTP
}

// GetPhone implements WhatsappOTPNode.
func (n *NodeCreateAuthenticatorWhatsappOTPSetup) GetPhone() string {
	return n.Phone
}

// GetCreateAuthenticatorStage implements CreateAuthenticatorPhoneOTPNode
func (n *NodeCreateAuthenticatorWhatsappOTPSetup) GetCreateAuthenticatorStage() authn.AuthenticationStage {
	return n.Stage
}

// GetSelectedPhoneNumberForPhoneOTP implements CreateAuthenticatorPhoneOTPNode
func (n *NodeCreateAuthenticatorWhatsappOTPSetup) GetSelectedPhoneNumberForPhoneOTP() string {
	return n.Phone
}

func (n *NodeCreateAuthenticatorWhatsappOTPSetup) Prepare(ctx *interaction.Context, graph *interaction.Graph) error {
	return nil
}

func (n *NodeCreateAuthenticatorWhatsappOTPSetup) GetEffects() ([]interaction.Effect, error) {
	return nil, nil
}

func (n *NodeCreateAuthenticatorWhatsappOTPSetup) DeriveEdges(graph *interaction.Graph) ([]interaction.Edge, error) {
	edges := []interaction.Edge{
		&EdgeCreateAuthenticatorWhatsappOTP{Stage: n.Stage, Authenticator: n.Authenticator},
	}
	return edges, nil
}
